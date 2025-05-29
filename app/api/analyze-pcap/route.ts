// app/api/analyze-pcap/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai"; //
import { createGroq } from "@ai-sdk/groq"; //
import db from "@/lib/neon-db"; //
const PcapParser = require('pcap-parser');
const PCAPNGParser = require('pcap-ng-parser');
import { Readable } from 'stream'; //

const MAX_SAMPLES_FOR_AI = 15; // Bisa dinaikkan sedikit jika perlu lebih banyak sampel error
const MAX_PACKETS_TO_PROCESS_FOR_STATS = 5000; //

// --- Fungsi Helper Timestamp (sama untuk kedua parser jika outputnya serupa) ---
function getTimestamp(packetHeader: any, isPcapNg: boolean = false, pcapNgPacket?: any, ifaceInfo?: any): string {
    if (isPcapNg && pcapNgPacket) {
        let timestampDate;
        const tsresol = ifaceInfo?.tsresol !== undefined ? Number(ifaceInfo.tsresol) : 6;
        if (pcapNgPacket.timestampHigh !== undefined && pcapNgPacket.timestampLow !== undefined) {
            // Logika dari pcapNgTimestampToDate
            const divisorForMs = BigInt(10 ** (Math.max(0, tsresol - 3)));
            const timestampBigInt = (BigInt(pcapNgPacket.timestampHigh) << 32n) | BigInt(pcapNgPacket.timestampLow);
            try {
                if (tsresol < 3) {
                    const multiplier = BigInt(10 ** (3 - tsresol));
                    timestampDate = new Date(Number(timestampBigInt * multiplier));
                } else {
                    timestampDate = new Date(Number(timestampBigInt / divisorForMs));
                }
            } catch (e) {
                console.warn(`[AI_TIMESTAMP_CONV_ERROR] pcapng: High=${pcapNgPacket.timestampHigh}, Low=${pcapNgPacket.timestampLow}, tsresol=${tsresol}. Error: ${e}`);
                timestampDate = new Date();
            }
        } else if (pcapNgPacket.timestampSeconds !== undefined) { // Fallback jika struktur mirip pcap
            timestampDate = new Date(pcapNgPacket.timestampSeconds * 1000 + (pcapNgPacket.timestampMicroseconds || 0) / 1000);
        } else {
            timestampDate = new Date();
            console.warn(`[AI_TIMESTAMP_CONV] Fallback timestamp for pcapng packet`);
        }
        return timestampDate.toISOString();
    } else { // Untuk pcap-parser
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
    const cleanupAndResolve = (data: any) => { /* ... (sama seperti sebelumnya) ... */
      if (!promiseResolved) {
        promiseResolved = true;
        console.log(`[AI_ORIGINAL_PARSER] Resolving for AI ${analysisId}. Packets: ${packetCounter}. Total time: ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`);
        if (parser) parser.removeAllListeners();
        if (readablePcapStream && !readablePcapStream.destroyed) { readablePcapStream.unpipe(parser); readablePcapStream.destroy(); }
        resolve(data);
      }
    };
    const cleanupAndReject = (error: Error) => { /* ... (sama seperti sebelumnya) ... */
      if (!promiseResolved) {
        promiseResolved = true;
        console.error(`[AI_ORIGINAL_PARSER] Rejecting for AI ${analysisId}. Error: ${error.message}`);
        if (parser) parser.removeAllListeners();
        if (readablePcapStream && !readablePcapStream.destroyed) { readablePcapStream.unpipe(parser); readablePcapStream.destroy(); }
        reject(error);
      }
    };

    parser.on('packet', (packet: any) => {
      if (promiseResolved) return;
      packetCounter++;
      const packetLength = packet.header.capturedLength;
      const timestamp = getTimestamp(packet.header, false);
      
      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = `Len ${packetLength}`;
      let isError = false, errorType: string | undefined = undefined;
      // Salin logika decoding detail dari parsePcapWithOriginalParser di get-packet-data
      // Termasuk pengisian isError dan errorType
      try {
        const linkLayerType = parser.linkLayerType !== undefined ? parser.linkLayerType : 1;
        let currentOffset = 0;
        if (linkLayerType === 1 && packet.data && packet.data.length >=14) {
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
                                if (flagsByte & 0x04) { isError = true; errorType = "TCP Reset"; } // RST flag
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

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < 5) ) { // Prioritaskan sampel error
        samplePacketsForAI.push({ no: packetCounter, timestamp, source: sourceIp, destination: destIp, protocol, length: packetLength, info, isError, errorType });
      }
      if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) { cleanupAndResolve(prepareAiData()); }
    });
    const prepareAiData = () => { /* ... (sama seperti sebelumnya) ... */
      const topProtocols = Object.entries(protocolStats).sort(([,a],[,b]) => b-a).slice(0, 7).reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});
      const calculatedTopTalkers = Object.entries(ipTraffic).map(([ip, data]) => ({ ip, packets: data.totalPackets, bytes: data.totalBytes })).sort((a, b) => b.bytes - a.bytes).slice(0, 7);
      return { statistics: { totalPacketsInFile: packetCounter, packetsProcessedForStats: packetCounter, protocols: topProtocols, topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "N/A", packets:0, bytes:0}], anomalyScore: Math.floor(Math.random() * 30) + 10, }, samplePackets: samplePacketsForAI, };
    };
    parser.on('end', () => { if (!promiseResolved) cleanupAndResolve(prepareAiData()); });
    parser.on('error', (err: Error) => { if (!promiseResolved) cleanupAndReject(new Error(`PcapParser stream error for AI: ${err.message}`)); });
    readablePcapStream.on('error', (err: Error) => { if (!promiseResolved) cleanupAndReject(new Error(`ReadableStream error for PcapParser AI: ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[AI_ORIGINAL_PARSER] ReadableStream closed prematurely for AI ${analysisId}.`); cleanupAndResolve(prepareAiData()); }});
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
    const cleanupAndFinish = (status: "resolved" | "rejected", dataOrError: any) => { /* ... (sama) ... */
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
      if (!pcapNgPacket.data) { return; } // Pastikan ada data buffer
      packetCounter++;

      const interfaceId = pcapNgPacket.interfaceId === undefined ? 0 : pcapNgPacket.interfaceId;
      const ifaceInfo = currentInterfaceInfo[interfaceId] || { linkLayerType: 1, tsresol: 6 };
      const timestamp = getTimestamp(null, true, pcapNgPacket, ifaceInfo);
      const packetLength = pcapNgPacket.capturedLength || pcapNgPacket.data.length;
      const packetDataBuffer = pcapNgPacket.data;

      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = `Len ${packetLength}`;
      let isError = false, errorType: string | undefined = undefined;
      // Salin logika decoding detail dari parsePcapNgWithNewParser di get-packet-data
      // Termasuk pengisian isError dan errorType
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
                                if (flagsByte & 0x04) { isError = true; errorType = "TCP Reset"; }
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

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < 5) ) {
        samplePacketsForAI.push({ no: packetCounter, timestamp, source: sourceIp, destination: destIp, protocol, length: packetLength, info, isError, errorType });
      }
      if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) { cleanupAndFinish("resolved", prepareAiData()); }
    });

    const prepareAiData = () => { /* ... (sama seperti di parsePcapForAIWithOriginalParser) ... */
        const topProtocols = Object.entries(protocolStats).sort(([,a],[,b]) => b-a).slice(0, 7).reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});
        const calculatedTopTalkers = Object.entries(ipTraffic).map(([ip, data]) => ({ ip, packets: data.totalPackets, bytes: data.totalBytes })).sort((a, b) => b.bytes - a.bytes).slice(0, 7);
        return { statistics: { totalPacketsInFile: packetCounter, packetsProcessedForStats: packetCounter, protocols: topProtocols, topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "N/A", packets:0, bytes:0}], anomalyScore: Math.floor(Math.random() * 30) + 10, }, samplePackets: samplePacketsForAI, };
    };
    parser.on('end', () => { if (!promiseResolved) cleanupAndFinish("resolved", prepareAiData()); });
    parser.on('error', (err: Error) => { if (!promiseResolved) cleanupAndFinish("rejected", new Error(`PCAPNGParser stream error for AI: ${err.message}`)); });
  });
}


const groqApiKey = process.env.GROQ_API_KEY; //
const modelNameFromEnv = process.env.GROQ_MODEL_NAME || "llama3-8b-8192"; //
let groqProvider: ReturnType<typeof createGroq> | null = null; //

if (groqApiKey && groqApiKey.trim() !== "") { //
  groqProvider = createGroq({ apiKey: groqApiKey }); //
  console.log("[API_ANALYZE_PCAP_CONFIG] Groq provider configured."); //
} else {
  console.error("[CRITICAL_CONFIG_ERROR] GROQ_API_KEY environment variable is missing or empty. AI features will be disabled."); //
}

function extractJsonFromString(text: string): string | null { //
    if (!text || text.trim() === "") {
        console.warn("[EXTRACT_JSON] AI returned empty or whitespace-only text.");
        return null; 
    }
    const markdownRegex = /```(?:json)?\s*([\s\S]*?)\s*```/; //
    const markdownMatch = text.match(markdownRegex);

    if (markdownMatch && markdownMatch[1]) {
        const extracted = markdownMatch[1].trim();
        return extracted;
    }
    const firstBrace = text.indexOf('{'); //
    const lastBrace = text.lastIndexOf('}'); //
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) { //
        const potentialJson = text.substring(firstBrace, lastBrace + 1); //
        try { JSON.parse(potentialJson); return potentialJson; } catch (e) { /* ignore */ }
    }
    return text.trim() === "" ? null : text.trim(); //
}

export async function POST(request: NextRequest) { //
  let analysisIdFromBody: string | undefined;
  let rawAnalysisTextForErrorLog: string | undefined; 
  let cleanedJsonTextForErrorLog: string | undefined; 

  try {
    const body = await request.json(); //
    analysisIdFromBody = body.analysisId; //
    console.log(`[API_ANALYZE_PCAP_V2_ERROR_REPORT] Received request for analysisId: ${analysisIdFromBody}`);

    if (!groqProvider) { //
      return NextResponse.json({ error: "AI Provider (Groq) is not configured." }, { status: 500 }); //
    }
    if (!analysisIdFromBody) { //
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 }); //
    }

    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromBody }); //
    if (!pcapRecord || !pcapRecord.blobUrl) { //
      return NextResponse.json({ error: "PCAP file metadata or URL not found" }, { status: 404 }); //
    }
    
    let extractedPcapData;
    const fileName = pcapRecord.originalName || pcapRecord.fileName || "unknown_file";
    if (fileName.toLowerCase().endsWith(".pcapng")) {
        console.log(`[API_ANALYZE_PCAP_V2_ERROR_REPORT] Using AI_PCAPNG_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapFileForAIWithPcapNgParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    } else {
        console.log(`[API_ANALYZE_PCAP_V2_ERROR_REPORT] Using AI_ORIGINAL_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapForAIWithOriginalParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    }

    if (!extractedPcapData || !extractedPcapData.samplePackets) { //
        return NextResponse.json({ error: "Failed to parse PCAP file data for AI." }, { status: 500 }); //
    }

    // Agregasi informasi error dari samplePacketsForAI
    const errorSummaryForAI: { [type: string]: { count: number, samplePacketNumbers: number[] } } = {};
    (extractedPcapData.samplePackets || []).forEach((packet: any) => {
        if (packet.isError && packet.errorType) {
            if (!errorSummaryForAI[packet.errorType]) {
                errorSummaryForAI[packet.errorType] = { count: 0, samplePacketNumbers: [] };
            }
            errorSummaryForAI[packet.errorType].count++;
            if (errorSummaryForAI[packet.errorType].samplePacketNumbers.length < 3) { // Batasi contoh paket per error
                errorSummaryForAI[packet.errorType].samplePacketNumbers.push(packet.no);
            }
        }
    });
    console.log(`[API_ANALYZE_PCAP_V2_ERROR_REPORT] Error summary for AI:`, JSON.stringify(errorSummaryForAI));


    const dataForAI = { //
      analysisId: analysisIdFromBody, //
      fileName: pcapRecord.originalName, //
      fileSize: pcapRecord.size, //
      ...extractedPcapData, //
      errorSummary: errorSummaryForAI, // Tambahkan ringkasan error
    };

    const { text: rawAnalysisText } = await generateText({ //
      model: groqProvider(modelNameFromEnv as any), //
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
        4.  **Error Analysis Report**: For each significant errorType in 'errorSummary' (if any):
            - errorType: (e.g., "TCP Reset")
            - count: (number of occurrences in sample)
            - description: Brief explanation of what this error type means.
            - possibleCauses: [Array of common reasons for this error]
            - troubleshootingSuggestions: [Array of actionable steps to investigate or fix]
            - relatedPacketSamples: [Array of 'no' from samplePackets that exhibit this error, if applicable]
        5.  List up to 5 specific, actionable findings (general security observations beyond packet errors). For each:
            - id, title, description, severity, confidence, recommendation, category, affectedHosts (optional), relatedPackets (optional, use 'no' from sample).
        6.  Identify up to 3-5 IOCs (ip, domain, url, hash) if strongly suggested. For each:
            - type, value, context, confidence.
        7.  Suggest 2-3 general recommendations for security improvement based on patterns. For each:
            - title, description, priority.
        8.  Create a brief timeline of up to 3-5 most significant events (use timestamps from sample packets or error summary). For each:
            - time, event, severity.

        Format your ENTIRE response strictly as a single JSON object.
        {
          "summary": "...",
          "threatLevel": "...",
          "trafficBehaviorScore": { "score": 0, "justification": "..." },
          "errorAnalysisReport": [ 
            { 
              "errorType": "TCP Reset", 
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
        Ensure the 'errorAnalysisReport' is populated based on 'errorSummary'. If no errors in summary, 'errorAnalysisReport' can be an empty array or contain a message like "No significant errors noted in the provided packet samples."
        The entire response MUST be ONLY the JSON object, starting with '{' and ending with '}'.
      `,
    });

    rawAnalysisTextForErrorLog = rawAnalysisText; //
    const cleanedJsonText = extractJsonFromString(rawAnalysisText); //
    cleanedJsonTextForErrorLog = cleanedJsonText; //

    if (!cleanedJsonText) { //
        throw new Error("AI returned empty or unrecoverable data after cleaning attempts.");
    }
    
    const aiAnalysis = JSON.parse(cleanedJsonText); //

    return NextResponse.json({ //
      success: true,
      analysis: {
        ...aiAnalysis,
        fileName: dataForAI.fileName, //
        fileSize: dataForAI.fileSize, //
        uploadDate: pcapRecord.createdAt.toISOString(),
      }
    });

  } catch (error) { //
    const analysisIdForLogError = analysisIdFromBody || 'unknown';
    console.error(`[API_ANALYZE_PCAP_V2_ERROR_REPORT] Error for analysisId: ${analysisIdForLogError}:`, error);
    const errorMessage = error instanceof Error ? error.message : "Unexpected AI analysis error.";
    if (error instanceof Error && (error.name === 'AI_LoadAPIKeyError' || error.message.includes("API key") || error.message.includes("authentication"))) { //
        return NextResponse.json({ error: "AI Provider API key error.", details: error.message }, { status: 500 }); //
    }
    if (error instanceof SyntaxError) {  //
        return NextResponse.json({ error: "Failed to parse AI response. Invalid JSON.", details: errorMessage }, { status: 500 }); //
    }
    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : "No stack" }, { status: 500 }); //
  }
}
