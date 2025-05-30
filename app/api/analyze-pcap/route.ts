// app/api/analyze-pcap/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { createGroq } from "@ai-sdk/groq";
import db from "@/lib/neon-db";
const PcapParser = require('pcap-parser');
const PCAPNGParser = require('pcap-ng-parser');
import { Readable } from 'stream';

const MAX_SAMPLES_FOR_AI = 150; 
const MAX_ERROR_INSTANCES_FOR_AI = 100; // Batasi jumlah instance error yang dikirim ke AI
const MAX_PACKETS_TO_PROCESS_FOR_STATS = 5000; 

// --- Fungsi Helper Timestamp (tetap sama) ---
function getTimestamp(packetHeader: any, isPcapNg: boolean = false, pcapNgPacket?: any, ifaceInfo?: any): string {
    if (isPcapNg && pcapNgPacket) {
        let timestampDate;
        const tsresolRaw = ifaceInfo?.tsresol !== undefined ? Number(ifaceInfo.tsresol) : 6;
        const isPowerOf2 = (tsresolRaw & 0x80) !== 0; 
        const tsresolValue = tsresolRaw & 0x7F; 

        let divisorBigInt: BigInt;
        if (isPowerOf2) {
            console.warn(`[AI_TIMESTAMP_CONV] Power-of-2 tsresol (${tsresolValue}) not fully implemented for precise BigInt conversion to ms. Defaulting to microsecond logic.`);
            divisorBigInt = BigInt(10 ** (6 - 3)); 
        } else {
            divisorBigInt = BigInt(10 ** (Math.max(0, tsresolValue - 3)));
        }

        const timestampBigInt = (BigInt(pcapNgPacket.timestampHigh) << 32n) | BigInt(pcapNgPacket.timestampLow);
        try {
            if (tsresolValue < 3 && !isPowerOf2) { 
                const multiplier = BigInt(10 ** (3 - tsresolValue));
                timestampDate = new Date(Number(timestampBigInt * multiplier));
            } else { 
                if (divisorBigInt === 0n) divisorBigInt = 1n; 
                const milliseconds = timestampBigInt / divisorBigInt;
                timestampDate = new Date(Number(milliseconds));
            }
        } catch (e) {
            console.warn(`[AI_TIMESTAMP_CONV_ERROR] pcapng: High=${pcapNgPacket.timestampHigh}, Low=${pcapNgPacket.timestampLow}, tsresolRaw=${tsresolRaw}. Error: ${e}`);
            timestampDate = new Date();
        }

        if (pcapNgPacket.timestampSeconds !== undefined && (pcapNgPacket.timestampHigh === undefined || pcapNgPacket.timestampLow === undefined)) { 
            timestampDate = new Date(pcapNgPacket.timestampSeconds * 1000 + (pcapNgPacket.timestampMicroseconds || 0) / 1000);
        } else if (!timestampDate) { 
            timestampDate = new Date();
            console.warn(`[AI_TIMESTAMP_CONV] Final fallback timestamp for pcapng packet`);
        }
        return timestampDate.toISOString();
    } else { 
        return new Date(packetHeader.timestampSeconds * 1000 + packetHeader.timestampMicroseconds / 1000).toISOString();
    }
}


// --- Parser untuk .pcap (menggunakan PcapParser) ---
async function parsePcapForAIWithOriginalParser(fileUrl: string, fileName: string, analysisId: string): Promise<any> {
  console.log(`[AI_ORIGINAL_PARSER_V2] Parsing .pcap for AI: ${fileName} (ID: ${analysisId})`);
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[AI_ORIGINAL_PARSER_V2] Failed to download .pcap file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = PcapParser.parse(readablePcapStream);

  let packetCounter = 0;
  const protocolStats: { [key: string]: number } = {};
  const samplePacketsForAI: Array<any> = [];
  let promiseResolved = false;
  const ipTraffic: { [ip: string]: { sentPackets: number, receivedPackets: number, sentBytes: number, receivedBytes: number, totalPackets: number, totalBytes: number } } = {};
  
  return new Promise((resolve, reject) => {
    const cleanupAndFinish = (status: "resolved" | "rejected", dataOrError: any) => {
      if (!promiseResolved) {
        promiseResolved = true;
        const outcome = status === "resolved" ? "Resolve" : "Reject";
        console.log(`[AI_ORIGINAL_PARSER_V2] Cleanup & ${outcome} for AI ${analysisId}. Packets: ${packetCounter}. Total time: ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`);
        if (parser) parser.removeAllListeners();
        if (readablePcapStream) {
            readablePcapStream.unpipe(parser);
            if (!readablePcapStream.destroyed) readablePcapStream.destroy();
            readablePcapStream.removeAllListeners();
        }
        if (status === "resolved") resolve(dataOrError); else reject(dataOrError);
      }
    };

    parser.on('packet', (packet: any) => {
      if (promiseResolved) return;
      packetCounter++;
      const packetLength = packet.header.capturedLength;
      const timestamp = getTimestamp(packet.header, false);
      
      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = `Len ${packetLength}`;
      let isError = false, errorType: string | undefined = undefined;
      let flags: string[] = [];

      try {
        const linkLayerType = parser.linkLayerType !== undefined ? parser.linkLayerType : 1;
        let currentOffset = 0; 
        if (linkLayerType === 1 && packet.data && packet.data.length >= 14) { 
            const etherType = packet.data.readUInt16BE(12);
            currentOffset = 14;
            if (etherType === 0x0800) { // IPv4
                protocol = "IPv4";
                if (packet.data.length >= currentOffset + 20) {
                    const ipHeaderIHL = (packet.data[currentOffset] & 0x0F);
                    const ipHeaderLength = ipHeaderIHL * 4;
                    if (packet.data.length >= currentOffset + ipHeaderLength) {
                        const ipHeader = packet.data.slice(currentOffset, currentOffset + ipHeaderLength);
                        sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                        destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                        const ipProtocolField = ipHeader[9];
                        info = `IPv4 ${sourceIp} -> ${destIp}`;
                        currentOffset += ipHeaderLength;
                        if (ipProtocolField === 1) { protocol = "ICMP"; info += ` ICMP`; }
                        else if (ipProtocolField === 6) { 
                            protocol = "TCP"; info += ` TCP`;
                            if (packet.data.length >= currentOffset + 20) {
                                const flagsByte = packet.data[currentOffset + 13];
                                if (flagsByte & 0x04) { flags.push("RST"); isError = true; errorType = "TCP Reset"; }
                                if (flagsByte & 0x02) flags.push("SYN");
                                if (flagsByte & 0x01) flags.push("FIN");
                                if (flagsByte & 0x10) flags.push("ACK");
                                const srcPort = packet.data.readUInt16BE(currentOffset);
                                const dstPort = packet.data.readUInt16BE(currentOffset + 2);
                                info = `${srcPort} → ${dstPort} [${flags.join(',')}] ${info.replace(`IPv4 ${sourceIp} -> ${destIp} TCP`, '')}`.trim();
                            } else { isError = true; errorType = "TruncatedTCP_AI"; }
                        }
                        else if (ipProtocolField === 17) { protocol = "UDP"; info += ` UDP`; }
                        else { protocol = `IPProto ${ipProtocolField}`; }
                    } else { isError = true; errorType = "TruncatedIP_AI"; }
                } else { isError = true; errorType = "ShortIP_AI"; }
            } else if (etherType === 0x86DD) { protocol = "IPv6"; }
            else if (etherType === 0x0806) { protocol = "ARP"; }
            else { protocol = `EtherType_0x${etherType.toString(16)}`; }
        } else { protocol = `LinkType_${linkLayerType}`; }
      } catch (e: any) { info = `Decode Err: ${e.message}`; isError = true; errorType = "DecodingErrorPcapAI"; }

      protocolStats[protocol] = (protocolStats[protocol] || 0) + 1;
      if (sourceIp !== "N/A") { if (!ipTraffic[sourceIp]) ipTraffic[sourceIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[sourceIp].sentPackets++; ipTraffic[sourceIp].sentBytes += packetLength; ipTraffic[sourceIp].totalPackets++; ipTraffic[sourceIp].totalBytes += packetLength;}
      if (destIp !== "N/A") { if (!ipTraffic[destIp]) ipTraffic[destIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[destIp].receivedPackets++; ipTraffic[destIp].receivedBytes += packetLength; ipTraffic[destIp].totalPackets++; ipTraffic[destIp].totalBytes += packetLength;}

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < Math.floor(MAX_SAMPLES_FOR_AI / 2)) ) {
        samplePacketsForAI.push({ no: packetCounter, timestamp, source: sourceIp, destination: destIp, protocol, length: packetLength, info, isError, errorType });
      }
      if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) {
        cleanupAndFinish("resolved", prepareAiData());
      }
    });

    const prepareAiData = () => {
      const topProtocols = Object.entries(protocolStats).sort(([,a],[,b]) => b-a).slice(0, 7).reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});
      const calculatedTopTalkers = Object.entries(ipTraffic).map(([ip, data]) => ({ ip, packets: data.totalPackets, bytes: data.totalBytes, sentPackets:data.sentPackets, receivedPackets:data.receivedPackets, sentBytes:data.sentBytes, receivedBytes:data.receivedBytes })).sort((a, b) => b.bytes - a.bytes).slice(0, 7);
      return { statistics: { totalPacketsInFile: packetCounter, packetsProcessedForStats: packetCounter, protocols: topProtocols, topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "N/A", packets:0, bytes:0, sentPackets:0, receivedPackets:0, sentBytes:0, receivedBytes:0}], anomalyScore: Math.floor(Math.random() * 30) + 10, }, samplePackets: samplePacketsForAI };
    };

    parser.on('end', () => { if (!promiseResolved) cleanupAndFinish("resolved", prepareAiData()); });
    parser.on('error', (err: Error) => { if (!promiseResolved) cleanupAndFinish("rejected", new Error(`PcapParser stream error for AI: ${err.message}`)); });
    readablePcapStream.on('error', (err: Error) => { if (!promiseResolved) cleanupAndFinish("rejected", new Error(`ReadableStream error for PcapParser AI: ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[AI_ORIGINAL_PARSER] ReadableStream closed prematurely for AI ${analysisId}.`); cleanupAndFinish("resolved", prepareAiData()); }});
  });
}

// --- Parser untuk .pcapng (menggunakan PCAPNGParser) ---
async function parsePcapFileForAIWithPcapNgParser(fileUrl: string, fileName: string, analysisId: string): Promise<any> {
  console.log(`[AI_PCAPNG_PARSER_V2] Parsing .pcapng for AI: ${fileName} (ID: ${analysisId})`);
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[AI_PCAPNG_PARSER_V2] Failed to download .pcapng file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = new PCAPNGParser();

  let packetCounter = 0;
  const protocolStats: { [key: string]: number } = {};
  const samplePacketsForAI: Array<any> = [];
  let promiseResolved = false;
  const ipTraffic: { [ip: string]: { sentPackets: number, receivedPackets: number, sentBytes: number, receivedBytes: number, totalPackets: number, totalBytes: number } } = {};
  let currentInterfaceInfo: any = {};
  let blockCounter = 0;
  let dataEventCounter = 0;
  
  return new Promise((resolve, reject) => {
    const cleanupAndFinish = (status: "resolved" | "rejected", dataOrError: any) => {
      if (!promiseResolved) { promiseResolved = true; const o=status==="resolved"?"Resolve":"Reject"; console.log(`[AI_PCAPNG_PARSER_V2] Cleanup & ${o} for ${analysisId}. Packets:${packetCounter}, DataEvents:${dataEventCounter}, Blocks:${blockCounter}. Time:${((Date.now()-functionStartTime)/1000).toFixed(2)}s`); if(parser)parser.removeAllListeners(); if(readablePcapStream){readablePcapStream.unpipe(parser); if(!readablePcapStream.destroyed)readablePcapStream.destroy(); readablePcapStream.removeAllListeners();} if(status==="resolved")resolve(dataOrError); else reject(dataOrError); }
    };
    readablePcapStream.on('error', (err: Error) => { cleanupAndFinish("rejected", new Error(`ReadableStream error (AI PcapNG): ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[AI_PCAPNG_PARSER_V2] ReadableStream closed prematurely for AI ${analysisId}.`); cleanupAndFinish("resolved", prepareAiData()); }});
    readablePcapStream.on('end', () => { console.log(`[AI_PCAPNG_PARSER_V2] ReadableStream END for AI ${analysisId}.`);});
    
    readablePcapStream.pipe(parser);

    parser.on('block', (block: any) => {
        blockCounter++;
        if (block.type === 'InterfaceDescriptionBlock') {
            currentInterfaceInfo[block.interfaceId] = { name: block.options?.if_name, linkLayerType: block.linkLayerType, tsresol: block.options?.if_tsresol !== undefined ? Number(block.options.if_tsresol) : 6 };
        }
    });

    parser.on('data', (pcapNgPacket: any) => {
      if (promiseResolved) return;
      dataEventCounter++;
      if (!pcapNgPacket.data) { return; }
      packetCounter++;

      const interfaceId = pcapNgPacket.interfaceId === undefined ? 0 : pcapNgPacket.interfaceId;
      const ifaceInfo = currentInterfaceInfo[interfaceId] || { linkLayerType: 1, tsresol: 6 };
      const timestamp = getTimestamp(null, true, pcapNgPacket, ifaceInfo);
      const packetLength = pcapNgPacket.capturedLength || pcapNgPacket.data.length;
      const packetDataBuffer = pcapNgPacket.data;

      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = `Len ${packetLength}`;
      let isError = false, errorType: string | undefined = undefined;
      let flags: string[] = [];

      try {
        const linkLayerType = ifaceInfo.linkLayerType;
        let currentOffset = 0;
        if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >=14) {
            const etherType = packetDataBuffer.readUInt16BE(12);
            currentOffset = 14;
            if (etherType === 0x0800) { // IPv4
                protocol = "IPv4";
                if (packetDataBuffer.length >= currentOffset + 20) {
                    const ipHeaderIHL = (packetDataBuffer[currentOffset] & 0x0F);
                    const ipHeaderLength = ipHeaderIHL * 4;
                    if (packetDataBuffer.length >= currentOffset + ipHeaderLength) {
                        const ipHeader = packetDataBuffer.slice(currentOffset, currentOffset + ipHeaderLength);
                        sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                        destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                        const ipProtocolField = ipHeader[9];
                        info = `IPv4 ${sourceIp} -> ${destIp}`;
                        currentOffset += ipHeaderLength;
                        if (ipProtocolField === 1) { protocol = "ICMP"; info += ` ICMP`; }
                        else if (ipProtocolField === 6) { 
                            protocol = "TCP"; info += ` TCP`;
                            if (packetDataBuffer.length >= currentOffset + 20) {
                                const flagsByte = packetDataBuffer[currentOffset + 13];
                                if (flagsByte & 0x04) { flags.push("RST"); isError = true; errorType = "TCP Reset"; }
                                if (flagsByte & 0x02) flags.push("SYN");
                                const srcPort = packetDataBuffer.readUInt16BE(currentOffset);
                                const dstPort = packetDataBuffer.readUInt16BE(currentOffset + 2);
                                info = `${srcPort} → ${dstPort} [${flags.join(',')}] ${info.replace(`IPv4 ${sourceIp} -> ${destIp} TCP`, '')}`.trim();
                            } else { isError = true; errorType = "TruncatedTCP_AI_NG"; }
                        }
                        else if (ipProtocolField === 17) { protocol = "UDP"; info += ` UDP`; }
                        else { protocol = `IPProto ${ipProtocolField}`; }
                    } else { isError = true; errorType = "TruncatedIP_AI_NG"; }
                } else { isError = true; errorType = "ShortIP_AI_NG"; }
            } else if (etherType === 0x86DD) { protocol = "IPv6"; }
            else if (etherType === 0x0806) { protocol = "ARP"; }
            else { protocol = `EtherType_0x${etherType.toString(16)}`; }
        } else { protocol = `LinkType_${linkLayerType}`; }
      } catch (e: any) { info = `Decode Err: ${e.message}`; isError = true; errorType = "DecodingErrorPcapNgAI"; }

      protocolStats[protocol] = (protocolStats[protocol] || 0) + 1;
      if (sourceIp !== "N/A") { if (!ipTraffic[sourceIp]) ipTraffic[sourceIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[sourceIp].sentPackets++; ipTraffic[sourceIp].sentBytes += packetLength; ipTraffic[sourceIp].totalPackets++; ipTraffic[sourceIp].totalBytes += packetLength;}
      if (destIp !== "N/A") { if (!ipTraffic[destIp]) ipTraffic[destIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[destIp].receivedPackets++; ipTraffic[destIp].receivedBytes += packetLength; ipTraffic[destIp].totalPackets++; ipTraffic[destIp].totalBytes += packetLength;}

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < Math.floor(MAX_SAMPLES_FOR_AI / 2)) ) {
        samplePacketsForAI.push({ no: packetCounter, timestamp, source: sourceIp, destination: destIp, protocol, length: packetLength, info, isError, errorType });
      }
      if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) { cleanupAndFinish("resolved", prepareAiData()); }
    });

    const prepareAiData = () => {
        const topProtocols = Object.entries(protocolStats).sort(([,a],[,b]) => b-a).slice(0, 7).reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});
        const calculatedTopTalkers = Object.entries(ipTraffic).map(([ip, data]) => ({ ip, packets: data.totalPackets, bytes: data.totalBytes, sentPackets:data.sentPackets, receivedPackets:data.receivedPackets, sentBytes:data.sentBytes, receivedBytes:data.receivedBytes })).sort((a, b) => b.bytes - a.bytes).slice(0, 7);
        return { statistics: { totalPacketsInFile: packetCounter, packetsProcessedForStats: packetCounter, protocols: topProtocols, topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "N/A", packets:0, bytes:0, sentPackets:0, receivedPackets:0, sentBytes:0, receivedBytes:0}], anomalyScore: Math.floor(Math.random() * 30) + 10, }, samplePackets: samplePacketsForAI, };
    };
    parser.on('end', () => { if (!promiseResolved) cleanupAndFinish("resolved", prepareAiData()); });
    parser.on('error', (err: Error) => { if (!promiseResolved) cleanupAndFinish("rejected", new Error(`PCAPNGParser stream error for AI: ${err.message}`)); });
  });
}


const groqApiKey = process.env.GROQ_API_KEY;
const modelNameFromEnv = process.env.GROQ_MODEL_NAME || "llama3-8b-8192";
let groqProvider: ReturnType<typeof createGroq> | null = null;

if (groqApiKey && groqApiKey.trim() !== "") {
  groqProvider = createGroq({ apiKey: groqApiKey });
  console.log("[API_ANALYZE_PCAP_CONFIG] Groq provider configured.");
} else {
  console.error("[CRITICAL_CONFIG_ERROR] GROQ_API_KEY environment variable is missing or empty. AI features will be disabled.");
}

function extractJsonFromString(text: string): string | null {
    if (!text || text.trim() === "") {
        console.warn("[EXTRACT_JSON] AI returned empty or whitespace-only text.");
        return null; 
    }
    const markdownRegex = /```(?:json)?\s*([\s\S]*?)\s*```/;
    const markdownMatch = text.match(markdownRegex);

    if (markdownMatch && markdownMatch[1]) {
        const extracted = markdownMatch[1].trim();
        return extracted;
    }
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
        const potentialJson = text.substring(firstBrace, lastBrace + 1);
        try { JSON.parse(potentialJson); return potentialJson; } catch (e) { /* ignore */ }
    }
    return text.trim() === "" ? null : text.trim();
}

export async function POST(request: NextRequest) {
  let analysisIdFromBody: string | undefined;
  let rawAnalysisTextForErrorLog: string | undefined; 
  let cleanedJsonTextForErrorLog: string | undefined; 

  try {
    const body = await request.json();
    analysisIdFromBody = body.analysisId;
    console.log(`[API_ANALYZE_PCAP_V4_PER_INSTANCE] Received request for analysisId: ${analysisIdFromBody}`);

    if (!groqProvider) {
      return NextResponse.json({ error: "AI Provider (Groq) is not configured." }, { status: 500 });
    }
    if (!analysisIdFromBody) {
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 });
    }

    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromBody });
    if (!pcapRecord || !pcapRecord.blobUrl) {
      return NextResponse.json({ error: "PCAP file metadata or URL not found" }, { status: 404 });
    }
    
    let extractedPcapData;
    const fileName = pcapRecord.originalName || pcapRecord.fileName || "unknown_file";
    if (fileName.toLowerCase().endsWith(".pcapng")) {
        console.log(`[API_ANALYZE_PCAP_V4_PER_INSTANCE] Using AI_PCAPNG_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapFileForAIWithPcapNgParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    } else {
        console.log(`[API_ANALYZE_PCAP_V4_PER_INSTANCE] Using AI_ORIGINAL_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapForAIWithOriginalParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    }

    if (!extractedPcapData || !extractedPcapData.samplePackets) {
        return NextResponse.json({ error: "Failed to parse PCAP file data for AI." }, { status: 500 });
    }

    // Kirim detail setiap paket error ke AI, bukan hanya summary
    const errorPacketsForAI = (extractedPcapData.samplePackets || [])
        .filter((packet: any) => packet.isError && packet.errorType)
        .map((packet: any) => ({ 
            no: packet.no,
            errorType: packet.errorType,
            infoFromParser: packet.info, // Info singkat dari parser kita
            source: packet.source,
            destination: packet.destination,
            protocol: packet.protocol,
            timestamp: packet.timestamp
        })).slice(0, MAX_ERROR_INSTANCES_FOR_AI); // Batasi jumlah instance error
    
    console.log(`[API_ANALYZE_PCAP_V4_PER_INSTANCE] Error packets for AI:`, JSON.stringify(errorPacketsForAI));


    const dataForAI = {
      analysisId: analysisIdFromBody,
      fileName: pcapRecord.originalName,
      fileSize: pcapRecord.size,
      statistics: extractedPcapData.statistics, // Kirim statistik umum
      // samplePackets: extractedPcapData.samplePackets, // Kirim semua sampel jika perlu untuk konteks umum
      errorPacketsForDetailedAnalysis: errorPacketsForAI, // Fokus pada error ini untuk analisis detail
    };

    const { text: rawAnalysisText } = await generateText({
      model: groqProvider(modelNameFromEnv as any),
      prompt:  `
        You are a network security expert analyzing PCAP data.
        File: "${dataForAI.fileName}" (size: ${dataForAI.fileSize} bytes, ID: ${dataForAI.analysisId}).
        
        Extracted Data:
        - General Statistics: ${JSON.stringify(dataForAI.statistics, null, 2)}
        - Specific Error Packets for Detailed Analysis (up to ${MAX_ERROR_INSTANCES_FOR_AI} instances, 'no' is packet number): ${JSON.stringify(dataForAI.errorPacketsForDetailedAnalysis, null, 2)}

        Based on THIS SPECIFIC data:
        1.  Provide a concise overall summary of findings and security posture.
        2.  Determine a threat level (low, medium, high, critical).
        3.  Provide a traffic behavior score (0-100, 0=benign, 100=malicious) with justification.
        4.  **Detailed Error Analysis**: For EACH packet in 'Specific Error Packets for Detailed Analysis' (if any):
            - packetNumber: (the 'no' field from the error packet)
            - errorType: (e.g., "TCP Reset", "TruncatedHeader", "TCP Retransmission", "TCP Dup ACK", "TCP Out-of-Order", "TCP Window Full", "TCP Zero Window", "TCP Spurious Retransmission", "Bad TCP Checksum", "ICMP Destination Unreachable", "ICMP Port Unreachable", "Malformed Packet", "DNS Error", "ARP Unsolicited Reply", "IP Fragmentation", "IP Reassembly Failure", "TLS Handshake Failure", "SSL Alert", "HTTP 4xx Error", "HTTP 5xx Error", "SIP 404 Not Found", "SIP 486 Busy Here", "SIP 503 Service Unavailable", "SIP 408 Request Timeout", "SIP 403 Forbidden", "SIP 400 Bad Request", "SIP 500 Server Internal Error", "SIP 603 Decline", "SIP 487 Request Terminated", "SIP 480 Temporarily Unavailable", "SIP Loop Detected", "SIP Too Many Hops", "SIP Unsupported Media Type", "SIP Request Retransmission", "RTP Packet Loss", "RTP Out-of-Order", "RTP Jitter", "RTP Silence", "RTP Late Packet", "RTP Payload Type Mismatch", "RTP Stream Not Detected", "RTCP Packet Loss Report", "RTCP High Delay", "RTCP Sender Report Missing", "RTCP Receiver Report Missing", "VoIP One-Way Audio", "VoIP No Audio", "VoIP Codec Mismatch", "VoIP Jitter Buffer Overflow", "VoIP Packet Discarded", "VoIP Latency Spike", "DTMF Transmission Error", "SRTP Decryption Failure", "SRTP Authentication Failure", "NAT Traversal Failure", "STUN Timeout", "TURN Allocation Failure", "ICE Negotiation Failure", "Codec Negotiation Failure" )
            - packetInfoFromParser: (the 'infoFromParser' field)
            - detailedExplanation: Provide an in-depth explanation of what this specific errorType means in the context of THIS packet (source, destination, protocol, and its parser-generated info).
            - probableCauseInThisContext: Based on this specific packet's details, what is the most probable cause for this error instance?
            - specificActionableRecommendations: [Array of 1-2 concise, actionable steps to investigate or fix THIS specific error instance.]
        5.  List all general security findings (observations beyond the specific errors analyzed above). For each:
            - id, title, description, severity, confidence, recommendation, category, affectedHosts (optional), relatedPackets (optional, use 'no' from general sample if relevant, not from errorPackets).
        6.  Identify all Indicators of Compromise (IOCs) if any are strongly suggested by the general traffic or specific errors. For each:
            - type, value, context, confidence.
        7.  Suggest all general recommendations for security improvement based on overall patterns. For each:
            - title, description, priority.
        8.  Create a brief timeline of all most significant events (can be from error packets or general observations). For each:
            - time, event, severity.

        Format your ENTIRE response strictly as a single JSON object.
        {
          "summary": "...",
          "threatLevel": "...",
          "trafficBehaviorScore": { "score": 0, "justification": "..." },
          "detailedErrorAnalysis": [ 
            { 
              "packetNumber": 0, 
              "errorType": "ExampleErrorType", 
              "packetInfoFromParser": "...",
              "detailedExplanation": "...",
              "probableCauseInThisContext": "...",
              "specificActionableRecommendations": ["...", "..."]
            } 
          ],
          "findings": [ { "id": "...", "title": "...", "description": "...", "severity": "...", "confidence": 0, "recommendation": "...", "category": "...", "affectedHosts": [], "relatedPackets": [] } ],
          "iocs": [ { "type": "ip", "value": "...", "context": "...", "confidence": 0 } ],
          "statistics": ${JSON.stringify(dataForAI.statistics)}, 
          "recommendations": [ { "title": "...", "description": "...", "priority": "..." } ],
          "timeline": [ { "time": "...", "event": "...", "severity": "..." } ]
        }
        Ensure 'detailedErrorAnalysis' is an array of objects, one for each error packet analyzed. If 'Specific Error Packets for Detailed Analysis' was empty, 'detailedErrorAnalysis' should be an empty array.
        The entire response MUST be ONLY the JSON object, starting with '{' and ending with '}'.
      `,
    });

    rawAnalysisTextForErrorLog = rawAnalysisText;
    const cleanedJsonText = extractJsonFromString(rawAnalysisText);
    cleanedJsonTextForErrorLog = cleanedJsonText;

    if (!cleanedJsonText) {
        throw new Error("AI returned empty or unrecoverable data after cleaning attempts.");
    }
    
    const aiAnalysis = JSON.parse(cleanedJsonText);

    return NextResponse.json({
      success: true,
      analysis: {
        ...aiAnalysis, // Ini adalah JSON yang diparsing dari respons teks AI
        // Sertakan kembali data yang mungkin berguna untuk frontend dan tidak selalu ada di respons AI
        fileName: dataForAI.fileName,
        fileSize: dataForAI.fileSize,
        uploadDate: pcapRecord.createdAt.toISOString(),
        samplePacketsForContext: extractedPcapData.samplePackets, // Kirim semua sampel paket asli untuk konteks
        statistics: aiAnalysis.statistics || dataForAI.statistics, // Fallback jika AI tidak mengembalikan statistik
      }
    });

  } catch (error) {
    const analysisIdForLogError = analysisIdFromBody || 'unknown';
    console.error(`[API_ANALYZE_PCAP_V4_PER_INSTANCE] Error for analysisId: ${analysisIdForLogError}:`, error);
    const errorMessage = error instanceof Error ? error.message : "Unexpected AI analysis error.";
    if (error instanceof Error && (error.name === 'AI_LoadAPIKeyError' || error.message.includes("API key") || error.message.includes("authentication"))) {
        return NextResponse.json({ error: "AI Provider API key error.", details: error.message }, { status: 500 });
    }
    if (error instanceof SyntaxError) { 
        return NextResponse.json({ error: "Failed to parse AI response. Invalid JSON.", details: errorMessage, rawText: rawAnalysisTextForErrorLog, cleanedText: cleanedJsonTextForErrorLog }, { status: 500 });
    }
    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : "No stack" }, { status: 500 });
  }
}
