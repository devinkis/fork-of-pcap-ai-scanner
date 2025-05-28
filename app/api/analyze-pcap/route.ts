// app/api/analyze-pcap/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { createGroq } from "@ai-sdk/groq";
import db from "@/lib/neon-db";
// const PcapParser = require('pcap-parser'); // Hapus impor lama
const PCAPNGParser = require('pcap-ng-parser'); // Impor library baru
import { Readable } from 'stream';

const MAX_SAMPLES_FOR_AI = 10;
const MAX_PACKETS_TO_PROCESS_FOR_STATS = 5000;

// Fungsi helper untuk konversi timestamp pcap-ng
function pcapNgTimestampToDate(timestampHigh: number, timestampLow: number): Date {
  const seconds = timestampHigh * (2**32 / 1e6) + timestampLow / 1e6;
  return new Date(seconds * 1000);
}

async function parsePcapFileForAIWithPcapNgParser(fileUrl: string, fileName: string): Promise<any> {
  console.log(`[API_ANALYZE_PCAP_PARSE_PCAPNG] Parsing PCAPNG/PCAP for AI: ${fileName} from ${fileUrl}`);
  
  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`Failed to download PCAP file for AI: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = new PCAPNGParser();

  let packetCounter = 0;
  const protocolGuessStats: { [key: string]: number } = {'UNKNOWN_L3': 0};
  const samplePacketsForAI: Array<any> = [];
  let promiseResolved = false;
  
  const ipTraffic: { [ip: string]: { sentPackets: number, receivedPackets: number, sentBytes: number, receivedBytes: number, totalPackets: number, totalBytes: number } } = {};
  let currentInterfaceInfo: any = null;

  return new Promise((resolve, reject) => {
    const resolveOnce = (data: any) => {
        if (!promiseResolved) {
          promiseResolved = true;
          // Hapus listener setelah promise diselesaikan
          if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
          readablePcapStream.unpipe(parser);
          readablePcapStream.destroy(); // Penting untuk menutup stream
          resolve(data);
        }
    };
    const rejectOnce = (error: Error) => {
        if (!promiseResolved) {
          promiseResolved = true;
           if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
          readablePcapStream.unpipe(parser);
          readablePcapStream.destroy();
          reject(error);
        }
    };

    readablePcapStream.pipe(parser);

    parser.on('interface', (interfaceDescription: any) => {
      console.log('[API_ANALYZE_PCAP_PARSE_PCAPNG] Interface Description Block:', interfaceDescription);
      currentInterfaceInfo = interfaceDescription;
    });

    parser.on('data', (parsedPcapNgPacket: any) => {
      if (promiseResolved || parsedPcapNgPacket.type !== 'EnhancedPacketBlock' || !parsedPcapNgPacket.data) {
        return;
      }

      packetCounter++;
      const packetDataBuffer = parsedPcapNgPacket.data;
      const timestamp = pcapNgTimestampToDate(parsedPcapNgPacket.timestampHigh, parsedPcapNgPacket.timestampLow).toISOString();
      const packetLength = parsedPcapNgPacket.capturedLength || packetDataBuffer.length;
      
      let guessedProtocol = "UNKNOWN_L3";
      let sourceIp = "N/A";
      let destIp = "N/A";
      let packetInfo = `Raw Link Layer Data (len ${packetLength})`;

      const linkLayerType = (currentInterfaceInfo && currentInterfaceInfo.id === parsedPcapNgPacket.interfaceId) ? currentInterfaceInfo.linkLayerType : 1;

      try {
          if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >= 14) { // Ethernet
              const etherType = packetDataBuffer.readUInt16BE(12);
              if (etherType === 0x0800) { // IPv4
                  if (packetDataBuffer.length >= 14 + 20) {
                      const ipHeaderStart = 14;
                      const ipHeaderIHL = (packetDataBuffer[ipHeaderStart] & 0x0F);
                      const ipHeaderLength = ipHeaderIHL * 4;
                      
                      if (packetDataBuffer.length >= ipHeaderStart + ipHeaderLength) {
                          const ipHeader = packetDataBuffer.slice(ipHeaderStart, ipHeaderStart + ipHeaderLength);
                          sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                          destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                          const ipProtocolField = ipHeader[9];
                          
                          let transportProtocolName = `IPProto_${ipProtocolField}`;
                          if (ipProtocolField === 6) transportProtocolName = "TCP";
                          else if (ipProtocolField === 17) transportProtocolName = "UDP";
                          else if (ipProtocolField === 1) transportProtocolName = "ICMP";
                          
                          guessedProtocol = transportProtocolName;
                          packetInfo = `IPv4 ${sourceIp} -> ${destIp} (${guessedProtocol})`;
                      } else { guessedProtocol = "IPv4_Truncated"; packetInfo = `IPv4 (Truncated Header)`; }
                  } else { guessedProtocol = "IPv4_Short"; packetInfo = `IPv4 (Too Short for Full Header)`; }
              } else if (etherType === 0x86DD) { guessedProtocol = "IPv6"; packetInfo = `IPv6`; }
              else if (etherType === 0x0806) { guessedProtocol = "ARP"; packetInfo = `ARP Packet`; }
              else { guessedProtocol = `EtherType_0x${etherType.toString(16)}`; packetInfo = `EtherType 0x${etherType.toString(16)}`; }
          } else if (linkLayerType !== 1) {
            guessedProtocol = `LinkType_${linkLayerType}`;
            packetInfo = `Packet with Link Layer Type ${linkLayerType}`;
          }
      } catch (e: any) {
          console.warn(`[API_ANALYZE_PCAP_PARSE_PCAPNG] Error decoding packet ${packetCounter} for AI: ${e.message}`);
          packetInfo = `Error decoding: ${e.message}`;
      }
      protocolGuessStats[guessedProtocol] = (protocolGuessStats[guessedProtocol] || 0) + 1;

      if (sourceIp !== "N/A") {
          if (!ipTraffic[sourceIp]) ipTraffic[sourceIp] = { sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0, totalPackets: 0, totalBytes: 0 };
          ipTraffic[sourceIp].sentPackets++; ipTraffic[sourceIp].sentBytes += packetLength;
          ipTraffic[sourceIp].totalPackets++; ipTraffic[sourceIp].totalBytes += packetLength;
      }
      if (destIp !== "N/A") {
          if (!ipTraffic[destIp]) ipTraffic[destIp] = { sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0, totalPackets: 0, totalBytes: 0 };
          ipTraffic[destIp].receivedPackets++; ipTraffic[destIp].receivedBytes += packetLength;
          ipTraffic[destIp].totalPackets++; ipTraffic[destIp].totalBytes += packetLength;
      }

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI) {
        samplePacketsForAI.push({
          no: packetCounter, timestamp: timestamp,
          source: sourceIp, destination: destIp,
          protocol: guessedProtocol, length: packetLength, info: packetInfo,
        });
      }

      if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) {
        console.warn(`[API_ANALYZE_PCAP_PARSE_PCAPNG] Reached AI packet processing limit: ${MAX_PACKETS_TO_PROCESS_FOR_STATS} for ${fileName}`);
        if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners('data'); // Hanya remove listener 'data' agar 'end' masih bisa terpanggil
        }
        resolveResults(); // Selesaikan parsing data
        return; 
      }
    });

    const resolveResults = () => {
      if (promiseResolved) return; 
      promiseResolved = true;

      const topProtocols = Object.entries(protocolGuessStats)
          .sort(([,a],[,b]) => b-a).slice(0, 5) 
          .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});

      const calculatedTopTalkers = Object.entries(ipTraffic)
          .map(([ip, data]) => ({ ip, packets: data.totalPackets, bytes: data.totalBytes, sentPackets:data.sentPackets, receivedPackets:data.receivedPackets, sentBytes:data.sentBytes, receivedBytes:data.receivedBytes }))
          .sort((a, b) => b.packets - a.packets).slice(0, 5); 

      resolve({
        statistics: {
          totalPacketsInFile: packetCounter, packetsProcessedForStats: packetCounter, 
          protocols: topProtocols,
          topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "No identifiable IP traffic", packets: 0, bytes: 0, sentPackets:0, receivedPackets:0, sentBytes:0, receivedBytes:0}],
          anomalyScore: Math.floor(Math.random() * 30) + 10, 
        },
        samplePackets: samplePacketsForAI,
        potentialThreatsIdentified: ["Basic scan by pcap-ng-parser, requires deeper payload inspection for detailed threats."],
        dataExfiltrationSigns: "Not determined from basic header parsing.",
      });
    };

    parser.on('end', () => {
      console.log(`[API_ANALYZE_PCAP_PARSE_PCAPNG] Finished PCAPNG stream for AI. Total packets: ${packetCounter} for ${fileName}`);
      resolveResults();
    });

    parser.on('error', (err: Error) => {
      console.error(`[API_ANALYZE_PCAP_PARSE_PCAPNG] Error parsing PCAPNG stream for AI (${fileName}):`, err);
      rejectOnce(new Error(`Error parsing PCAPNG stream for AI: ${err.message}`));
    });
  }); 
}


const groqApiKey = process.env.GROQ_API_KEY;
const modelNameFromEnv = process.env.GROQ_MODEL_NAME || "llama3-8b-8192";
let groqProvider: ReturnType<typeof createGroq> | null = null;

if (groqApiKey && groqApiKey.trim() !== "") {
  groqProvider = createGroq({ apiKey: groqApiKey });
  console.log("[API_ANALYZE_PCAP_CONFIG] Groq provider configured using createGroq.");
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

    if (!groqProvider) {
      return NextResponse.json({ error: "AI Provider (Groq) is not configured. API key might be missing." }, { status: 500 });
    }
    if (!analysisIdFromBody) {
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 });
    }

    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromBody });
    if (!pcapRecord || !pcapRecord.blobUrl) {
      return NextResponse.json({ error: "PCAP file metadata or URL not found" }, { status: 404 });
    }
    
    const extractedPcapData = await parsePcapFileForAIWithPcapNgParser(pcapRecord.blobUrl, pcapRecord.originalName);
    if (!extractedPcapData) {
        return NextResponse.json({ error: "Failed to parse PCAP file data for AI." }, { status: 500 });
    }

    const dataForAI = {
      analysisId: analysisIdFromBody,
      fileName: pcapRecord.originalName,
      fileSize: pcapRecord.size,
      ...extractedPcapData,
    };

    const { text: rawAnalysisText } = await generateText({
      model: groqProvider(modelNameFromEnv as any),
      prompt:  `
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
        3. Provide a traffic behavior score from 0 (very benign) to 100 (highly anomalous/malicious) with a brief justification.
        4. List up to 5 specific, actionable findings. For each finding:
            - id: a unique string for this finding (e.g., "finding-dns-tunnel-01")
            - title: a short, descriptive title
            - description: a detailed explanation of what was observed
            - severity: (low, medium, high, critical)
            - confidence: (0-100) your confidence in this finding
            - recommendation: a specific action to take
            - category: (malware, anomaly, exfiltration, vulnerability, reconnaissance, policy-violation, benign-but-noteworthy)
            - affectedHosts: (optional) list of IPs primarily involved in this finding (use actual IPs if identified in parsing)
            - relatedPackets: (optional) reference 'no' field from sample packets if applicable (e.g., [1, 5])
        5. Identify up to 3-5 Indicators of Compromise (IOCs) if any are strongly suggested by the data. For each IOC:
            - type: (ip, domain, url, hash)
            - value: the IOC value (use actual IPs or domains if identified)
            - context: why this is an IOC based on the data
            - confidence: (0-100)
        6. Suggest 2-3 general recommendations for improving security based on patterns seen.
            - title
            - description
            - priority: (low, medium, high)
        7. Create a brief timeline of up to 3-5 most significant events if discernible from the provided data (use timestamps from sample packets if relevant, use 'no' field for reference).
            - time: (ISO string or relative time like "Packet Sample #1 Timestamp")
            - event: description of the event
            - severity: (info, warning, error)

        Format your entire response strictly as a single JSON object with the following structure:
        {
          "summary": "...",
          "threatLevel": "...",
          "trafficBehaviorScore": { "score": 0, "justification": "..." },
          "findings": [ { "id": "...", "title": "...", "description": "...", "severity": "...", "confidence": 0, "recommendation": "...", "category": "...", "affectedHosts": [], "relatedPackets": [] } ],
          "iocs": [ { "type": "ip", "value": "...", "context": "...", "confidence": 0 } ],
          "statistics": ${JSON.stringify(dataForAI.statistics)}, 
          "recommendations": [ { "title": "...", "description": "...", "priority": "..." } ],
          "timeline": [ { "time": "...", "event": "...", "severity": "..." } ]
        }
        Your response MUST start with '{' and end with '}'. Do NOT include any text or markdown formatting (like \`\`\`json) before or after the JSON object itself. The entire response must be ONLY the JSON object. If the provided PCAP data is insufficient or unclear for a detailed analysis, you MUST still return a valid JSON object with a 'summary' field explaining this, and other fields like 'findings' and 'iocs' can be empty arrays, and trafficBehaviorScore can have a low score with justification "insufficient data".
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
        // Menambahkan informasi file asli ke respons AI jika belum ada dari AI
        fileName: dataForAI.fileName,
        fileSize: dataForAI.fileSize,
        uploadDate: pcapRecord.createdAt.toISOString(), // Asumsi createdAt adalah Date object
      }
    });

  } catch (error) {
    const analysisIdForLogError = analysisIdFromBody || 'unknown';
    console.error(`[API_ANALYZE_PCAP] Error for analysisId: ${analysisIdForLogError}:`, error);
    const errorMessage = error instanceof Error ? error.message : "Unexpected AI analysis error.";
    if (error instanceof Error && (error.name === 'AI_LoadAPIKeyError' || error.message.includes("API key") || error.message.includes("authentication"))) {
        return NextResponse.json({ error: "AI Provider API key error.", details: error.message }, { status: 500 });
    }
    if (error instanceof SyntaxError) { 
        return NextResponse.json({ error: "Failed to parse AI response. Invalid JSON.", details: errorMessage }, { status: 500 });
    }
    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : "No stack" }, { status: 500 });
  }
}
