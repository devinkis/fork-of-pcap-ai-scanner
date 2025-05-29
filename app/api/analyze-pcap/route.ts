// app/api/analyze-pcap/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { createGroq } from "@ai-sdk/groq";
import db from "@/lib/neon-db";
const PcapParser = require('pcap-parser');
const PCAPNGParser = require('pcap-ng-parser');
import { Readable } from 'stream';

const MAX_SAMPLES_FOR_AI = 1000; // Jumlah sampel paket untuk dikirim ke AI
const MAX_PACKETS_TO_PROCESS_FOR_STATS = 5000; // Batas pemrosesan paket untuk statistik umum

// --- Fungsi Helper Timestamp ---
function getTimestamp(packetHeader: any, isPcapNg: boolean = false, pcapNgPacket?: any, ifaceInfo?: any): string {
    if (isPcapNg && pcapNgPacket) {
        let timestampDate;
        // tsresol: log base 10 of the resolution. Default 6 means microseconds.
        // if_tsresol option in pcapng Interface Description Block.
        // Bit 7 indicates if it's negative power of 10 (most common) or power of 2.
        const tsresolRaw = ifaceInfo?.tsresol !== undefined ? Number(ifaceInfo.tsresol) : 6;
        const isPowerOf2 = (tsresolRaw & 0x80) !== 0; // Check MSB
        const tsresolValue = tsresolRaw & 0x7F; // Actual resolution value

        let divisorBigInt: BigInt;
        if (isPowerOf2) {
            // For power of 2, resolution is 2^(-tsresolValue). To get to milliseconds (10^-3):
            // We need to convert timestamp (units of 2^-tsresolValue seconds) to milliseconds.
            // timestamp_units * (2^-tsresolValue seconds/unit) * (1000 ms/second)
            // = timestamp_units * 1000 / (2^tsresolValue)
            // This can be complex with BigInt if not careful with floating points.
            // Simpler: convert to a common base like nanoseconds first if tsresolValue is high.
            // For now, let's assume common case is power of 10.
            console.warn(`[AI_TIMESTAMP_CONV] Power-of-2 tsresol (${tsresolValue}) not fully implemented for precise BigInt conversion to ms. Defaulting to microsecond logic.`);
            divisorBigInt = BigInt(10 ** (6 - 3)); // Fallback to microsecond logic
        } else {
             // Power of 10, resolution is 10^(-tsresolValue) seconds.
             // To convert to milliseconds (10^-3 seconds):
             // timestamp_units * (10^-tsresolValue seconds/unit) * (1000 ms/second)
             // = timestamp_units / (10^(tsresolValue - 3))
            divisorBigInt = BigInt(10 ** (Math.max(0, tsresolValue - 3)));
        }

        const timestampBigInt = (BigInt(pcapNgPacket.timestampHigh) << 32n) | BigInt(pcapNgPacket.timestampLow);
        try {
            if (tsresolValue < 3 && !isPowerOf2) { // e.g., seconds, deciseconds, centiseconds (powers of 10)
                const multiplier = BigInt(10 ** (3 - tsresolValue));
                timestampDate = new Date(Number(timestampBigInt * multiplier));
            } else { // e.g., milliseconds, microseconds, nanoseconds etc. (powers of 10)
                if (divisorBigInt === 0n) divisorBigInt = 1n; // Avoid division by zero
                const milliseconds = timestampBigInt / divisorBigInt;
                timestampDate = new Date(Number(milliseconds));
            }
        } catch (e) {
            console.warn(`[AI_TIMESTAMP_CONV_ERROR] pcapng: High=${pcapNgPacket.timestampHigh}, Low=${pcapNgPacket.timestampLow}, tsresolRaw=${tsresolRaw}. Error: ${e}`);
            timestampDate = new Date();
        }

        if (pcapNgPacket.timestampSeconds !== undefined && (pcapNgPacket.timestampHigh === undefined || pcapNgPacket.timestampLow === undefined)) { // Fallback for PacketBlock in pcapng
            timestampDate = new Date(pcapNgPacket.timestampSeconds * 1000 + (pcapNgPacket.timestampMicroseconds || 0) / 1000);
        } else if (!timestampDate) { // Final fallback
            timestampDate = new Date();
            console.warn(`[AI_TIMESTAMP_CONV] Final fallback timestamp for pcapng packet`);
        }
        return timestampDate.toISOString();
    } else { // For pcap-parser (legacy .pcap)
        return new Date(packetHeader.timestampSeconds * 1000 + packetHeader.timestampMicroseconds / 1000).toISOString();
    }
}


// --- Parser untuk .pcap (menggunakan PcapParser) ---
async function parsePcapForAIWithOriginalParser(fileUrl: string, fileName: string, analysisId: string): Promise<any> {
  console.log(`[AI_ORIGINAL_PARSER] Parsing .pcap for AI: ${fileName} (ID: ${analysisId})`);
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[AI_ORIGINAL_PARSER] Failed to download .pcap file: ${pcapResponse.statusText}`);
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
        console.log(`[AI_ORIGINAL_PARSER] Cleanup & ${outcome} for AI ${analysisId}. Packets: ${packetCounter}. Total time: ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`);
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
                                // Add other flags if needed for info string
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

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < Math.floor(MAX_SAMPLES_FOR_AI / 3)) ) {
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
  console.log(`[AI_PCAPNG_PARSER] Parsing .pcapng for AI: ${fileName} (ID: ${analysisId})`);
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[AI_PCAPNG_PARSER] Failed to download .pcapng file: ${pcapResponse.statusText}`);
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
      if (!promiseResolved) { promiseResolved = true; const o=status==="resolved"?"Resolve":"Reject"; console.log(`[AI_PCAPNG_PARSER] Cleanup & ${o} for ${analysisId}. Packets:${packetCounter}, DataEvents:${dataEventCounter}, Blocks:${blockCounter}. Time:${((Date.now()-functionStartTime)/1000).toFixed(2)}s`); if(parser)parser.removeAllListeners(); if(readablePcapStream){readablePcapStream.unpipe(parser); if(!readablePcapStream.destroyed)readablePcapStream.destroy(); readablePcapStream.removeAllListeners();} if(status==="resolved")resolve(dataOrError); else reject(dataOrError); }
    };
    readablePcapStream.on('error', (err: Error) => { cleanupAndFinish("rejected", new Error(`ReadableStream error (AI PcapNG): ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[AI_PCAPNG_PARSER] ReadableStream closed prematurely for AI ${analysisId}.`); cleanupAndFinish("resolved", prepareAiData()); }});
    readablePcapStream.on('end', () => { console.log(`[AI_PCAPNG_PARSER] ReadableStream END for AI ${analysisId}.`);});
    
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
                                // ... (add other flag checks if needed for info)
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

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < Math.floor(MAX_SAMPLES_FOR_AI / 3)) ) {
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
    console.log(`[API_ANALYZE_PCAP_V3_ERROR_PROMPT] Received request for analysisId: ${analysisIdFromBody}`);

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
        console.log(`[API_ANALYZE_PCAP_V3_ERROR_PROMPT] Using AI_PCAPNG_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapFileForAIWithPcapNgParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    } else {
        console.log(`[API_ANALYZE_PCAP_V3_ERROR_PROMPT] Using AI_ORIGINAL_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapForAIWithOriginalParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    }

    if (!extractedPcapData || !extractedPcapData.samplePackets) {
        return NextResponse.json({ error: "Failed to parse PCAP file data for AI." }, { status: 500 });
    }

    const errorSummaryForAI: { [type: string]: { count: number, samplePacketNumbers: number[] } } = {};
    (extractedPcapData.samplePackets || []).forEach((packet: any) => {
        if (packet.isError && packet.errorType) {
            if (!errorSummaryForAI[packet.errorType]) {
                errorSummaryForAI[packet.errorType] = { count: 0, samplePacketNumbers: [] };
            }
            errorSummaryForAI[packet.errorType].count++;
            if (errorSummaryForAI[packet.errorType].samplePacketNumbers.length < 3) {
                errorSummaryForAI[packet.errorType].samplePacketNumbers.push(packet.no);
            }
        }
    });
    console.log(`[API_ANALYZE_PCAP_V3_ERROR_PROMPT] Error summary for AI:`, JSON.stringify(errorSummaryForAI));


    const dataForAI = {
      analysisId: analysisIdFromBody,
      fileName: pcapRecord.originalName,
      fileSize: pcapRecord.size,
      ...extractedPcapData,
      errorSummary: errorSummaryForAI, 
    };

    const { text: rawAnalysisText } = await generateText({
      model: groqProvider(modelNameFromEnv as any),
      prompt:  `
        You are a network security expert analyzing PCAP data.
        File: "${dataForAI.fileName}" (size: ${dataForAI.fileSize} bytes, ID: ${dataForAI.analysisId}).
        
        Extracted Data:
        - Statistics: ${JSON.stringify(dataForAI.statistics, null, 2)}
        - Sample Packets (up to ${MAX_SAMPLES_FOR_AI}, 'no' is packet num, 'isError' & 'errorType' indicate issues): ${JSON.stringify(dataForAI.samplePackets, null, 2)}
        - Summary of Errors in Sample Packets: ${JSON.stringify(dataForAI.errorSummary, null, 2)}

        Based on THIS SPECIFIC data:
        1.  Provide a concise summary of findings and overall security posture.
        2.  Determine a threat level (low, medium, high, critical).
        3.  Provide a traffic behavior score (0-100, 0=benign, 100=malicious) with justification.
        4.  **Error Analysis Report**: For each significant errorType in 'errorSummary' (if any, max 5 types):
            - errorType: (e.g., "TCP Reset")
            - count: (number of occurrences in sample)
            - description: Brief explanation of what this error type means in a network context.
            - possibleCauses: [Array of 2-3 common reasons for this error]
            - troubleshootingSuggestions: [Array of 2-3 actionable steps to investigate or fix]
            - relatedPacketSamples: [Array of 'no' from samplePackets that exhibit this error, if applicable and available in the summary]
        5.  List up to 5 specific, actionable findings (general security observations beyond packet errors). For each:
            - id: a unique string for this finding (e.g., "finding-dns-tunnel-01")
            - title: a short, descriptive title
            - description: a detailed explanation of what was observed
            - severity: (low, medium, high, critical)
            - confidence: (0-100) your confidence in this finding
            - recommendation: a specific action to take
            - category: (malware, anomaly, exfiltration, vulnerability, reconnaissance, policy-violation, benign-but-noteworthy)
            - affectedHosts: (optional) list of IPs primarily involved in this finding (use actual IPs if identified in parsing)
            - relatedPackets: (optional) reference 'no' field from sample packets if applicable (e.g., [1, 5])
        6.  Identify up to 3-5 Indicators of Compromise (IOCs) if any are strongly suggested by the data. For each IOC:
            - type: (ip, domain, url, hash)
            - value: the IOC value (use actual IPs or domains if identified)
            - context: why this is an IOC based on the data
            - confidence: (0-100)
        7.  Suggest 2-3 general recommendations for security improvement based on patterns seen. For each:
            - title
            - description
            - priority: (low, medium, high)
        8.  Create a brief timeline of up to 3-5 most significant events if discernible from the provided data (use timestamps from sample packets or error summary). For each:
            - time: (ISO string or relative time like "Packet Sample #1 Timestamp")
            - event: description of the event
            - severity: (info, warning, error)

        Format your ENTIRE response strictly as a single JSON object.
        {
          "summary": "...",
          "threatLevel": "...",
          "trafficBehaviorScore": { "score": 0, "justification": "..." },
          "errorAnalysisReport": [ 
            { 
              "errorType": "ExampleErrorType", 
              "count": 0, 
              "description": "...",
              "possibleCauses": ["...", "..."], 
              "troubleshootingSuggestions": ["...", "..."],
              "relatedPacketSamples": []
            } 
          ],
          "findings": [ { "id": "...", "title": "...", "description": "...", "severity": "...", "confidence": 0, "recommendation": "...", "category": "...", "affectedHosts": [], "relatedPackets": [] } ],
          "iocs": [ { "type": "ip", "value": "...", "context": "...", "confidence": 0 } ],
          "statistics": ${JSON.stringify(dataForAI.statistics)}, 
          "recommendations": [ { "title": "...", "description": "...", "priority": "..." } ],
          "timeline": [ { "time": "...", "event": "...", "severity": "..." } ]
        }
        Ensure the 'errorAnalysisReport' is populated based on 'errorSummary'. If no errors in summary, 'errorAnalysisReport' can be an empty array.
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
        ...aiAnalysis,
        fileName: dataForAI.fileName,
        fileSize: dataForAI.fileSize,
        uploadDate: pcapRecord.createdAt.toISOString(),
        // Menyertakan samplePacketsForContext agar frontend bisa menggunakannya untuk animasi
        samplePacketsForContext: dataForAI.samplePackets, 
        // Jika AI tidak selalu mengembalikan statistics, kita bisa fallback ke data asli
        statistics: aiAnalysis.statistics || dataForAI.statistics,
      }
    });

  } catch (error) {
    const analysisIdForLogError = analysisIdFromBody || 'unknown';
    console.error(`[API_ANALYZE_PCAP_V3_ERROR_PROMPT] Error for analysisId: ${analysisIdForLogError}:`, error);
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
```

**Perubahan Utama pada `/app/api/analyze-pcap/route.ts`:**

1.  **Struktur `getTimestamp`**: Fungsi `getTimestamp` disesuaikan agar bisa menerima argumen untuk membedakan antara parsing `.pcap` dan `.pcapng`, terutama untuk menangani `timestampHigh`, `timestampLow`, dan `tsresol` dari `pcap-ng-parser`.
2.  **`parsePcapForAIWithOriginalParser`**:
    * Logika decoding paket di dalamnya sekarang lebih detail dan mencoba mengisi `isError` dan `errorType` untuk kondisi seperti TCP Reset atau header terpotong. **Anda harus memverifikasi dan menyesuaikan ini dengan logika decoding `.pcap` Anda yang sudah terbukti benar.**
    * Menambahkan `isError` dan `errorType` ke objek paket yang disimpan di `samplePacketsForAI`.
3.  **`parsePcapFileForAIWithPcapNgParser`**:
    * Menggunakan `getTimestamp` dengan flag `isPcapNg = true`.
    * Mengambil `ifaceInfo.tsresol` dari `currentInterfaceInfo` untuk akurasi timestamp.
    * Logika decoding paket di dalamnya juga sekarang lebih detail dan mencoba mengisi `isError` dan `errorType`. **Anda juga harus memverifikasi dan menyesuaikan ini.**
    * Menambahkan `isError` dan `errorType` ke objek paket yang disimpan di `samplePacketsForAI`.
4.  **Agregasi `errorSummaryForAI`**: Di dalam fungsi `POST` utama, setelah data dari parser didapatkan, `errorSummaryForAI` dibuat dengan menghitung `errorType` dari `extractedPcapData.samplePackets`.
5.  **Prompt AI Diperbarui**:
    * Sekarang menyertakan `errorSummary` sebagai input.
    * Secara eksplisit meminta AI untuk menghasilkan `errorAnalysisReport` dengan format yang ditentukan (errorType, count, description, possibleCauses, troubleshootingSuggestions, relatedPacketSamples).
6.  **Respons JSON ke Frontend**:
    * Memastikan `samplePacketsForContext: dataForAI.samplePackets` ditambahkan ke objek `analysis` yang dikirim kembali. Ini penting agar frontend memiliki detail paket sampel yang bisa digunakan untuk visualisasi error.
    * Menambahkan fallback untuk `statistics` jika AI tidak mengembalikannya.

**PENTING SEKALI (Pengulangan):**
* **Logika Decoding di Fungsi Parser AI**: Anda **HARUS** mereview dengan sangat teliti dan menyesuaikan blok kode decoding di dalam `parser.on('packet', ...)` pada `parsePcapForAIWithOriginalParser` dan `parser.on('data', ...)` pada `parsePcapFileForAIWithPcapNgParser`. Pastikan logika tersebut mengekstrak informasi header dengan benar dan, yang paling penting, **mengisi variabel `isError` dan `errorType` secara akurat** berdasarkan kondisi yang Anda anggap sebagai error (misalnya, flag TCP RST, header yang tidak lengkap, checksum yang salah jika Anda memeriksanya, dll.). Akurasi `errorSummaryForAI` sangat bergantung pada ini.

Setelah Anda menerapkan dan memverifikasi kode ini, dan melakukan deploy, frontend (`components/ai-insights.tsx`) yang telah kita siapkan seharusnya bisa menampilkan "Detailed Error Analysis" berdasarkan output
