import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import db from "@/lib/neon-db";
import pcap, { PcapSession, Packet, PcapPacket } from 'pcap'; // Impor dari pcap
import fs from 'fs';
import os from 'os';
import path from 'path';

async function parsePcapFileWithNodePcap(fileUrl: string, fileName: string, analysisId: string): Promise<any> {
  console.log(`[PARSE_NODE_PCAP] Attempting to parse PCAP from URL: ${fileUrl} (File: ${fileName})`);
  const tempDir = path.join(os.tmpdir(), 'pcap-analysis');
  const tempFilePath = path.join(tempDir, `${analysisId}-${fileName}`);

  try {
    // Buat direktori sementara jika belum ada
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    // 1. Unduh file PCAP ke path sementara
    console.log(`[PARSE_NODE_PCAP] Downloading PCAP to ${tempFilePath}`);
    const pcapResponse = await fetch(fileUrl);
    if (!pcapResponse.ok || !pcapResponse.body) {
      throw new Error(`Failed to download PCAP file: ${pcapResponse.statusText}`);
    }
    const arrayBuffer = await pcapResponse.arrayBuffer();
    fs.writeFileSync(tempFilePath, Buffer.from(arrayBuffer));
    console.log(`[PARSE_NODE_PCAP] PCAP file downloaded successfully to ${tempFilePath}`);

    // 2. Buat sesi pcap offline
    // Pastikan Anda menggunakan tipe yang benar untuk PcapSession jika ada type definitions
    const pcapSession: PcapSession = pcap.createOfflineSession(tempFilePath, "");
    
    let packetCounter = 0;
    const protocolStats: { [key: string]: number } = {};
    const samplePacketsForAI: Array<any> = [];
    const MAX_SAMPLES_FOR_AI = 15;
    const MAX_PACKETS_TO_PROCESS_FOR_STATS = 5000; // Batasi untuk performa

    const ipTraffic: { [ip: string]: { sentPackets: number, receivedPackets: number, sentBytes: number, receivedBytes: number } } = {};

    return new Promise((resolve, reject) => {
      pcapSession.on('packet', (rawPacket: Buffer) => {
        packetCounter++;
        // node-pcap mengembalikan buffer mentah, kita perlu decode
        const packet: Packet = pcap.decode.packet(rawPacket) as Packet; // Lakukan type assertion jika perlu

        const packetLength = packet.header.caplen; // captured length
        const timestamp = new Date(packet.header.time_seconds * 1000 + packet.header.time_ms / 1000).toISOString();
        
        let sourceIp = "N/A";
        let destIp = "N/A";
        let sourcePort: number | undefined;
        let destPort: number | undefined;
        let layer3ProtocolName = "UnknownL3";
        let layer4ProtocolName = "UnknownL4";
        let applicationLayerInfo = "";
        let packetSummary = `Packet ${packetCounter}`;

        try {
            if (packet.link) { // Layer 2
                protocolStats[packet.link.name] = (protocolStats[packet.link.name] || 0) + 1;
                if (packet.link.ip) { // Layer 3 (IP)
                    const ipPacket = packet.link.ip;
                    layer3ProtocolName = ipPacket.protocol_name || 'IP_UNKNOWN';
                    protocolStats[layer3ProtocolName] = (protocolStats[layer3ProtocolName] || 0) + 1;
                    sourceIp = ipPacket.saddr?.toString() || "N/A";
                    destIp = ipPacket.daddr?.toString() || "N/A";
                    packetSummary = `${layer3ProtocolName} ${sourceIp} -> ${destIp}`;

                    if (ipPacket.tcp) { // Layer 4 (TCP)
                        layer4ProtocolName = 'TCP';
                        protocolStats[layer4ProtocolName] = (protocolStats[layer4ProtocolName] || 0) + 1;
                        const tcpSegment = ipPacket.tcp;
                        sourcePort = tcpSegment.sport;
                        destPort = tcpSegment.dport;
                        packetSummary += ` (${layer4ProtocolName}) ${sourcePort}->${destPort}`;
                         if (destPort === 80 || sourcePort === 80) applicationLayerInfo = "HTTP";
                         else if (destPort === 443 || sourcePort === 443) applicationLayerInfo = "HTTPS/TLS";
                         else if (destPort === 53 || sourcePort === 53) applicationLayerInfo = "DNS/TCP";
                    } else if (ipPacket.udp) { // Layer 4 (UDP)
                        layer4ProtocolName = 'UDP';
                        protocolStats[layer4ProtocolName] = (protocolStats[layer4ProtocolName] || 0) + 1;
                        const udpDatagram = ipPacket.udp;
                        sourcePort = udpDatagram.sport;
                        destPort = udpDatagram.dport;
                        packetSummary += ` (${layer4ProtocolName}) ${sourcePort}->${destPort}`;
                        if (destPort === 53 || sourcePort === 53) applicationLayerInfo = "DNS/UDP";
                    } else if (ipPacket.icmp) {
                        layer4ProtocolName = 'ICMP';
                        protocolStats[layer4ProtocolName] = (protocolStats[layer4ProtocolName] || 0) + 1;
                        applicationLayerInfo = `ICMP Type: ${ipPacket.icmp.type}, Code: ${ipPacket.icmp.code}`;
                    }
                } else if (packet.link.arp) {
                    layer3ProtocolName = 'ARP';
                    protocolStats[layer3ProtocolName] = (protocolStats[layer3ProtocolName] || 0) + 1;
                    packetSummary = `ARP ${packet.link.arp.sender_pa?.toString()} -> ${packet.link.arp.target_pa?.toString()}`;
                }
            }
        } catch(e: any) {
            console.warn(`[PARSE_NODE_PCAP] Error decoding individual packet ${packetCounter}: ${e.message}`);
        }
        
        if (sourceIp !== "N/A") {
            ipTraffic[sourceIp] = ipTraffic[sourceIp] || { sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0 };
            ipTraffic[sourceIp].sentPackets++;
            ipTraffic[sourceIp].sentBytes += packetLength;
        }
        if (destIp !== "N/A") {
            ipTraffic[destIp] = ipTraffic[destIp] || { sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0 };
            ipTraffic[destIp].receivedPackets++;
            ipTraffic[destIp].receivedBytes += packetLength;
        }

        if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI) {
          samplePacketsForAI.push({
            no: packetCounter,
            timestamp: timestamp,
            source: sourcePort !== undefined ? `${sourceIp}:${sourcePort}` : sourceIp,
            destination: destPort !== undefined ? `${destIp}:${destPort}` : destIp,
            protocolL3: layer3ProtocolName,
            protocolL4: layer4ProtocolName,
            length: packetLength,
            info: applicationLayerInfo || packetSummary,
          });
        }

        if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) {
          console.warn(`[PARSE_NODE_PCAP] Reached packet processing limit for stats: ${MAX_PACKETS_TO_PROCESS_FOR_STATS} for file ${fileName}`);
          pcapSession.close(); // Hentikan sesi jika batas tercapai
          resolveResults();
          return;
        }
      });

      const resolveResults = () => {
          // Hanya resolve sekali
        if (!(resolve as any).__resolved) {
            (resolve as any).__resolved = true; 
            const topTalkers = Object.entries(ipTraffic)
            .map(([ip, data]) => ({ 
                ip, 
                packets: data.sentPackets + data.receivedPackets, 
                bytes: data.sentBytes + data.receivedBytes,
                sentPackets: data.sentPackets,
                receivedPackets: data.receivedPackets,
                sentBytes: data.sentBytes,
                receivedBytes: data.receivedBytes
                }))
            .sort((a, b) => b.packets - a.packets)
            .slice(0, 5);
            
            resolve({
            statistics: {
                totalPacketsInFile: packetCounter, // Mungkin tidak akurat jika sesi ditutup lebih awal
                packetsProcessedForStats: packetCounter, 
                protocols: protocolStats,
                topTalkers: topTalkers,
                anomalyScore: Math.floor(Math.random() * 30) + 10, 
            },
            samplePackets: samplePacketsForAI,
            potentialThreatsIdentified: ["Scan with node-pcap, details depend on parsing."],
            dataExfiltrationSigns: "Further analysis on decoded data needed.",
            });
        }
      };

      pcapSession.on('complete', () => {
        console.log(`[PARSE_NODE_PCAP] Finished reading PCAP file. Total packets: ${packetCounter} for file: ${fileName}`);
        resolveResults();
      });

      pcapSession.on('error', (err: Error) => {
        console.error(`[PARSE_NODE_PCAP] Error reading PCAP session for ${fileName}:`, err);
         if (!(reject as any).__rejected) {
            (reject as any).__rejected = true;
            reject(new Error(`Error reading PCAP session: ${err.message}`));
        }
      });

    }); // Akhir dari new Promise
  } catch (error) {
    console.error(`[PARSE_NODE_PCAP] Outer error in parsePcapFileWithNodePcap for ${fileName}:`, error);
    throw error; 
  } finally {
    // Hapus file sementara setelah selesai
    if (fs.existsSync(tempFilePath)) {
      try {
        fs.unlinkSync(tempFilePath);
        console.log(`[PARSE_NODE_PCAP] Temporary file ${tempFilePath} deleted.`);
      } catch (e) {
        console.error(`[PARSE_NODE_PCAP] Error deleting temporary file ${tempFilePath}:`, e);
      }
    }
  }
}
// --- Akhir dari implementasi parsePcapFileWithNodePcap ---


// --- Sisa kode (OpenRouter client, extractJsonFromString, dan fungsi POST handler) ---
// Tetap sama seperti versi sebelumnya, pastikan pemanggilan fungsi parsing diubah ke parsePcapFileWithNodePcap.

const openRouterApiKey = process.env.OPENROUTER_API_KEY;
const openRouterBaseURL = process.env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1";
const modelNameFromEnv = process.env.OPENROUTER_MODEL_NAME || "mistralai/mistral-7b-instruct";

let openRouterProvider: ReturnType<typeof createOpenAI> | null = null;

if (openRouterApiKey && openRouterApiKey.trim() !== "") {
  openRouterProvider = createOpenAI({
    apiKey: openRouterApiKey,
    baseURL: openRouterBaseURL,
  });
  console.log("[API_ANALYZE_PCAP_CONFIG] OpenRouter provider configured using createOpenAI.");
} else {
  console.error("[CRITICAL_CONFIG_ERROR] OPENROUTER_API_KEY environment variable is missing or empty. AI features will be disabled.");
}

function extractJsonFromString(text: string): string | null {
    console.log("[EXTRACT_JSON] Original AI text length:", text.length);
    const regex = /```(?:json)?\s*([\s\S]*?)\s*```/;
    const match = text.match(regex);
  
    if (match && match[1]) {
      console.log("[EXTRACT_JSON] JSON found inside markdown backticks.");
      return match[1].trim();
    }
    
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      const potentialJson = text.substring(firstBrace, lastBrace + 1);
      try {
          JSON.parse(potentialJson);
          console.log("[EXTRACT_JSON] JSON found by brace matching.");
          return potentialJson;
      } catch (e) {
          console.warn("[EXTRACT_JSON] Brace matching did not yield valid JSON, returning original text for parsing attempt.");
      }
    }
    
    console.log("[EXTRACT_JSON] No markdown backticks or clear JSON object found, returning original trimmed text.");
    return text.trim(); 
}

export async function POST(request: NextRequest) {
  let analysisIdFromBody: string | undefined;
  let rawAnalysisTextForErrorLog: string | undefined; 
  let cleanedJsonTextForErrorLog: string | undefined; 

  try {
    const body = await request.json();
    analysisIdFromBody = body.analysisId;
    console.log(`[API_ANALYZE_PCAP] Received request for analysisId: ${analysisIdFromBody}`);

    if (!openRouterProvider) {
      console.error("[API_ANALYZE_PCAP] OpenRouter provider is not configured. OPENROUTER_API_KEY is likely missing or empty.");
      return NextResponse.json({ error: "AI Provider (OpenRouter) is not configured. API key might be missing." }, { status: 500 });
    }

    if (!analysisIdFromBody) {
      console.error("[API_ANALYZE_PCAP] No analysis ID provided in the request body.");
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 });
    }

    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromBody });

    if (!pcapRecord) {
      console.error(`[API_ANALYZE_PCAP] PCAP record not found in DB for analysisId: ${analysisIdFromBody}`);
      return NextResponse.json({ error: "PCAP file metadata not found for this analysis" }, { status: 404 });
    }
    if (!pcapRecord.blobUrl) {
      console.error(`[API_ANALYZE_PCAP] PCAP record found, but blobUrl is missing for analysisId: ${analysisIdFromBody}`);
      return NextResponse.json({ error: "PCAP file URL not found for this analysis" }, { status: 404 });
    }
    
    const pcapFileUrl = pcapRecord.blobUrl;
    const pcapFileName = pcapRecord.originalName;
    const pcapFileSize = pcapRecord.size;

    console.log(`[API_ANALYZE_PCAP] Analyzing PCAP: ${pcapFileName} (URL: ${pcapFileUrl}, Size: ${pcapFileSize} bytes) for analysisId: ${analysisIdFromBody}`);

    // Menggunakan fungsi parsing yang baru dengan node-pcap
    const extractedPcapData = await parsePcapFileWithNodePcap(pcapFileUrl, pcapFileName, analysisIdFromBody);

    if (!extractedPcapData) {
        console.error(`[API_ANALYZE_PCAP] Failed to parse PCAP data for analysisId: ${analysisIdFromBody}`);
        return NextResponse.json({ error: "Failed to parse PCAP file data." }, { status: 500 });
    }

    const dataForAI = {
      analysisId: analysisIdFromBody,
      fileName: pcapFileName,
      fileSize: pcapFileSize,
      ...extractedPcapData,
    };

    console.log(`[API_ANALYZE_PCAP] Data prepared for AI model for analysisId: ${analysisIdFromBody}, Stats:`, dataForAI.statistics);

    const { text: rawAnalysisText } = await generateText({
      model: openRouterProvider(modelNameFromEnv as any),
      prompt: `
        You are a network security expert analyzing PCAP data.
        The data is from file: "${dataForAI.fileName}" (size: ${dataForAI.fileSize} bytes, analysis ID: ${dataForAI.analysisId}).
        
        Key Extracted PCAP Data:
        - Overall Statistics: ${JSON.stringify(dataForAI.statistics, null, 2)}
        - Sample Packets (first ${MAX_SAMPLES_FOR_AI} packets or less, 'no' field is packet number): ${JSON.stringify(dataForAI.samplePackets, null, 2)}
        - Preliminary Scan Results (if any): 
          - Potential Threats: ${JSON.stringify(dataForAI.potentialThreatsIdentified)}
          - Data Exfiltration Signs: ${JSON.stringify(dataForAI.dataExfiltrationSigns)}

        Based on THIS SPECIFIC data:
        1. Provide a concise summary of your findings. What is the overall security posture observed from this data?
        2. Determine a threat level (low, medium, high, critical).
        3. List up to 5 specific, actionable findings. For each finding:
            - id: a unique string for this finding (e.g., "finding-dns-tunnel-01")
            - title: a short, descriptive title
            - description: a detailed explanation of what was observed
            - severity: (low, medium, high, critical)
            - confidence: (0-100) your confidence in this finding
            - recommendation: a specific action to take
            - category: (malware, anomaly, exfiltration, vulnerability, reconnaissance, policy-violation, benign-but-noteworthy)
            - affectedHosts: (optional) list of IPs primarily involved in this finding
            - relatedPackets: (optional) reference 'no' field from sample packets if applicable (e.g., [1, 5])
        4. Identify up to 3-5 Indicators of Compromise (IOCs) if any are strongly suggested by the data. For each IOC:
            - type: (ip, domain, url, hash)
            - value: the IOC value
            - context: why this is an IOC based on the data
            - confidence: (0-100)
        5. Suggest 2-3 general recommendations for improving security based on patterns seen. For each recommendation:
            - title
            - description
            - priority: (low, medium, high)
        6. Create a brief timeline of up to 3-5 most significant events if discernible from the provided data (use timestamps from sample packets if relevant, use 'no' field for reference). For each timeline event:
            - time: (ISO string or relative time like "Packet Sample #1 Timestamp")
            - event: description of the event
            - severity: (info, warning, error)

        Format your entire response strictly as a single JSON object with the following structure:
        {
          "summary": "...",
          "threatLevel": "...",
          "findings": [ { "id": "...", "title": "...", ... } ],
          "iocs": [ { "type": "...", "value": "...", ... } ],
          "statistics": ${JSON.stringify(dataForAI.statistics)},
          "recommendations": [ { "title": "...", ... } ],
          "timeline": [ { "time": "...", "event": "...", "severity": "..." } ]
        }
        Your response MUST start with '{' and end with '}'. Do NOT include any text or markdown formatting (like \`\`\`json) before or after the JSON object itself. The entire response must be ONLY the JSON object.
      `,
    });

    rawAnalysisTextForErrorLog = rawAnalysisText; 
    console.log(`[API_ANALYZE_PCAP] AI analysis raw response received (length: ${rawAnalysisText.length}) for analysisId: ${analysisIdFromBody}`);
    
    const cleanedJsonText = extractJsonFromString(rawAnalysisText);
    cleanedJsonTextForErrorLog = cleanedJsonText; 

    if (!cleanedJsonText) {
        console.error(`[API_ANALYZE_PCAP] Failed to extract valid JSON from AI response for analysisId: ${analysisIdFromBody}. Raw text was:`, rawAnalysisText);
        throw new Error("AI returned data in an unrecoverable format or empty after cleaning.");
    }
    
    console.log(`[API_ANALYZE_PCAP] Cleaned JSON text for parsing (length: ${cleanedJsonText.length}):`, cleanedJsonText.substring(0, 200) + "...");
    const aiAnalysis = JSON.parse(cleanedJsonText); 
    console.log(`[API_ANALYZE_PCAP] AI analysis parsed successfully for analysisId: ${analysisIdFromBody}`);

    return NextResponse.json({
      success: true,
      analysis: aiAnalysis,
    });

  } catch (error) {
    const analysisIdForLogError = analysisIdFromBody || request.nextUrl.searchParams.get('analysisId') || 'unknown';
    console.error(`[API_ANALYZE_PCAP] Error analyzing packet data for analysisId: ${analysisIdForLogError}:`, error);
    
    const errorMessage = error instanceof Error ? error.message : "An unexpected error occurred during AI analysis.";
    
    if (error instanceof Error && (error.name === 'AI_LoadAPIKeyError' || error.message.includes("API key") || error.message.includes("authentication"))) {
        return NextResponse.json({ error: "AI Provider API key is missing, invalid, or not authorized. Please check server configuration and OpenRouter account status.", details: error.message }, { status: 500 });
    }
    if (error instanceof SyntaxError) { 
        console.error(`[API_ANALYZE_PCAP] JSON Parsing Error. Original AI text was (first 500 chars):`, rawAnalysisTextForErrorLog?.substring(0, 500));
        console.error(`[API_ANALYZE_PCAP] JSON Parsing Error. Cleaned text was (first 500 chars):`, cleanedJsonTextForErrorLog?.substring(0, 500));
        return NextResponse.json({ error: "Failed to parse AI response even after cleaning. The AI might have returned an invalid JSON structure.", details: errorMessage }, { status: 500 });
    }

    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : "No stack available" }, { status: 500 });
  }
}
