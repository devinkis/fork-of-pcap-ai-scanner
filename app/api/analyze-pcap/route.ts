// Path: devinkis/fork-of-pcap-ai-scanner/fork-of-pcap-ai-scanner-da289a06468a369b1b56ff7cba2dd3429fc5431a/app/api/analyze-pcap/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
// --- PERUBAHAN MULAI ---
// import { createOpenAI } from "@ai-sdk/openai"; // Hapus atau komentari baris ini
import { createGroq } from "@ai-sdk/groq"; // Tambahkan impor untuk Groq
// --- PERUBAHAN SELESAI ---
import db from "@/lib/neon-db";
import PcapParser from 'pcap-parser';
import { Readable } from 'stream';

const MAX_SAMPLES_FOR_AI = 10;
const MAX_PACKETS_TO_PROCESS_FOR_STATS = 5000;

async function parsePcapFileWithReadableStream(fileUrl: string, fileName: string): Promise<any> {
  console.log(`[PARSE_PCAP_PARSER_STREAM] Attempting to parse PCAP from URL: ${fileUrl} (File: ${fileName})`);
  try {
    const pcapResponse = await fetch(fileUrl);
    if (!pcapResponse.ok || !pcapResponse.body) {
      throw new Error(`Failed to download PCAP file: ${pcapResponse.statusText}`);
    }
    const arrayBuffer = await pcapResponse.arrayBuffer();
    const pcapBuffer = Buffer.from(arrayBuffer);

    const readablePcapStream = Readable.from(pcapBuffer);
    const parser = PcapParser.parse(readablePcapStream);

    let packetCounter = 0;
    const protocolGuessStats: { [key: string]: number } = {'UNKNOWN_L3': 0};
    const samplePacketsForAI: Array<any> = [];
    let promiseResolved = false;
    
    const ipTraffic: { [ip: string]: { sentPackets: number, receivedPackets: number, sentBytes: number, receivedBytes: number, totalPackets: number, totalBytes: number } } = {};

    return new Promise((resolve, reject) => {
      const resolveOnce = (data: any) => {
        if (!promiseResolved) {
          promiseResolved = true;
          resolve(data);
        }
      };
      const rejectOnce = (error: Error) => {
        if (!promiseResolved) {
          promiseResolved = true;
          reject(error);
        }
      };

      parser.on('packet', (packet: any) => {
        if (promiseResolved) return;

        packetCounter++;
        const packetLength = packet.header.capturedLength;
        const timestamp = new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000).toISOString();
        
        let guessedProtocol = "UNKNOWN_L3";
        let sourceIp = "N/A";
        let destIp = "N/A";
        let packetInfo = `Raw Link Layer Data (len ${packetLength})`;

        try {
            if (packet.data && packet.data.length >= 14) { // Ethernet Header
                const etherType = packet.data.readUInt16BE(12);
                if (etherType === 0x0800) { // IPv4
                    if (packet.data.length >= 14 + 20) { // Min IPv4 Header
                        const ipHeaderStart = 14;
                        const ipHeaderIHL = (packet.data[ipHeaderStart] & 0x0F);
                        const ipHeaderLength = ipHeaderIHL * 4;
                        
                        if (packet.data.length >= ipHeaderStart + ipHeaderLength) {
                            const ipHeader = packet.data.slice(ipHeaderStart, ipHeaderStart + ipHeaderLength);
                            sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                            destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                            const ipProtocolField = ipHeader[9];
                            
                            let transportProtocolName = `IPProto_${ipProtocolField}`;
                            if (ipProtocolField === 6) transportProtocolName = "TCP";
                            else if (ipProtocolField === 17) transportProtocolName = "UDP";
                            else if (ipProtocolField === 1) transportProtocolName = "ICMP";
                            
                            guessedProtocol = transportProtocolName;
                            packetInfo = `IPv4 ${sourceIp} -> ${destIp} (${guessedProtocol})`;
                        } else {
                             guessedProtocol = "IPv4_Truncated";
                             packetInfo = `IPv4 (Truncated Header)`;
                        }
                    } else {
                        guessedProtocol = "IPv4_Short";
                        packetInfo = `IPv4 (Too Short for Full Header)`;
                    }
                } else if (etherType === 0x86DD) { // IPv6
                    guessedProtocol = "IPv6";
                    packetInfo = `IPv6 (further parsing needed)`;
                } else if (etherType === 0x0806) { // ARP
                    guessedProtocol = "ARP";
                    packetInfo = `ARP Packet`;
                } else {
                    guessedProtocol = `EtherType_0x${etherType.toString(16)}`;
                    packetInfo = `EtherType 0x${etherType.toString(16)}`;
                }
            }
        } catch (e: any) {
            console.warn(`[PARSE_PCAP_PARSER_STREAM] Error decoding individual packet ${packetCounter}: ${e.message}`);
            packetInfo = `Error decoding: ${e.message}`;
        }
        protocolGuessStats[guessedProtocol] = (protocolGuessStats[guessedProtocol] || 0) + 1;

        if (sourceIp !== "N/A") {
            if (!ipTraffic[sourceIp]) ipTraffic[sourceIp] = { sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0, totalPackets: 0, totalBytes: 0 };
            ipTraffic[sourceIp].sentPackets++;
            ipTraffic[sourceIp].sentBytes += packetLength;
            ipTraffic[sourceIp].totalPackets++;
            ipTraffic[sourceIp].totalBytes += packetLength;
        }
        if (destIp !== "N/A") {
            if (!ipTraffic[destIp]) ipTraffic[destIp] = { sentPackets: 0, receivedPackets: 0, sentBytes: 0, receivedBytes: 0, totalPackets: 0, totalBytes: 0 };
            ipTraffic[destIp].receivedPackets++;
            ipTraffic[destIp].receivedBytes += packetLength;
            ipTraffic[destIp].totalPackets++;
            ipTraffic[destIp].totalBytes += packetLength;
        }

        if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI) {
          samplePacketsForAI.push({
            no: packetCounter,
            timestamp: timestamp,
            source: sourceIp,
            destination: destIp,
            protocol: guessedProtocol,
            length: packetLength,
            info: packetInfo,
          });
        }

        if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) {
          console.warn(`[PARSE_PCAP_PARSER_STREAM] Reached packet processing limit for stats: ${MAX_PACKETS_TO_PROCESS_FOR_STATS} for file ${fileName}`);
          if (parser && typeof parser.removeAllListeners === 'function') {
             parser.removeAllListeners('packet');
             parser.removeAllListeners('end');
             parser.removeAllListeners('error');
          }
          resolveResults();
          return; 
        }
      });

      const resolveResults = () => {
        if (promiseResolved) return; 
        promiseResolved = true;

        const topProtocols = Object.entries(protocolGuessStats)
            .sort(([,a],[,b]) => b-a)
            .slice(0, 5) 
            .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});

        const calculatedTopTalkers = Object.entries(ipTraffic)
            .map(([ip, data]) => ({
                ip,
                packets: data.totalPackets, 
                bytes: data.totalBytes,    
                sentPackets: data.sentPackets,
                receivedPackets: data.receivedPackets,
                sentBytes: data.sentBytes,
                receivedBytes: data.receivedBytes
            }))
            .sort((a, b) => b.packets - a.packets) 
            .slice(0, 5); 

        resolve({
          statistics: {
            totalPacketsInFile: packetCounter, 
            packetsProcessedForStats: packetCounter, 
            protocols: topProtocols,
            topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "No identifiable IP traffic", packets: 0, bytes: 0, sentPackets:0, receivedPackets:0, sentBytes:0, receivedBytes:0}],
            anomalyScore: Math.floor(Math.random() * 30) + 10, 
          },
          samplePackets: samplePacketsForAI,
          potentialThreatsIdentified: ["Basic scan by pcap-parser, requires deeper payload inspection for detailed threats."],
          dataExfiltrationSigns: "Not determined from basic header parsing.",
        });
      };

      parser.on('end', () => {
        console.log(`[PARSE_PCAP_PARSER_STREAM] Finished reading PCAP stream. Total packets emitted: ${packetCounter} for file: ${fileName}`);
        resolveResults();
      });

      parser.on('error', (err: Error) => {
        console.error(`[PARSE_PCAP_PARSER_STREAM] Error reading PCAP stream for ${fileName}:`, err);
        rejectOnce(new Error(`Error reading PCAP stream: ${err.message}`));
      });
    }); 
  } catch (error) {
    console.error(`[PARSE_PCAP_PARSER_STREAM] Outer error in parsePcapFileWithReadableStream for ${fileName}:`, error);
    throw error; 
  }
}

// --- PERUBAHAN MULAI ---
const groqApiKey = process.env.GROQ_API_KEY;
// Groq API base URL biasanya tidak perlu di-override, SDK akan menanganinya.
// const groqBaseURL = process.env.GROQ_BASE_URL; // Jika diperlukan
const modelNameFromEnv = process.env.GROQ_MODEL_NAME || "llama3-8b-8192"; // Ganti dengan model Groq default Anda

let groqProvider: ReturnType<typeof createGroq> | null = null;

if (groqApiKey && groqApiKey.trim() !== "") {
  groqProvider = createGroq({
    apiKey: groqApiKey,
    // baseURL: groqBaseURL, // Hanya jika Anda perlu override base URL Groq
  });
  console.log("[API_ANALYZE_PCAP_CONFIG] Groq provider configured using createGroq.");
} else {
  console.error("[CRITICAL_CONFIG_ERROR] GROQ_API_KEY environment variable is missing or empty. AI features will be disabled.");
}
// --- PERUBAHAN SELESAI ---


function extractJsonFromString(text: string): string | null {
    // ... (fungsi ini tetap sama)
    if (!text || text.trim() === "") {
        console.warn("[EXTRACT_JSON] AI returned empty or whitespace-only text.");
        return null; 
    }
    console.log("[EXTRACT_JSON] Original AI text (first 500 chars):", text.substring(0, 500));
    const markdownRegex = /```(?:json)?\s*([\s\S]*?)\s*```/;
    const markdownMatch = text.match(markdownRegex);

    if (markdownMatch && markdownMatch[1]) {
        const extracted = markdownMatch[1].trim();
        console.log("[EXTRACT_JSON] JSON found inside markdown backticks. Length:", extracted.length);
        return extracted;
    }
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
        const potentialJson = text.substring(firstBrace, lastBrace + 1);
        try {
            JSON.parse(potentialJson); 
            console.log("[EXTRACT_JSON] JSON found by brace matching. Length:", potentialJson.length);
            return potentialJson;
        } catch (e) {
            console.warn("[EXTRACT_JSON] Brace matching did not yield valid JSON, returning original text for parsing attempt.");
        }
    }
    const trimmedText = text.trim();
    console.log("[EXTRACT_JSON] No markdown or clear JSON object found, returning original trimmed text. Length:", trimmedText.length);
    return trimmedText === "" ? null : trimmedText;
}

export async function POST(request: NextRequest) {
  let analysisIdFromBody: string | undefined;
  let rawAnalysisTextForErrorLog: string | undefined; 
  let cleanedJsonTextForErrorLog: string | undefined; 

  try {
    const body = await request.json();
    analysisIdFromBody = body.analysisId;
    console.log(`[API_ANALYZE_PCAP] Received request for analysisId: ${analysisIdFromBody}`);

    // --- PERUBAHAN MULAI ---
    if (!groqProvider) {
      console.error("[API_ANALYZE_PCAP] Groq provider is not configured. GROQ_API_KEY is likely missing or empty.");
      return NextResponse.json({ error: "AI Provider (Groq) is not configured. API key might be missing." }, { status: 500 });
    }
    // --- PERUBAHAN SELESAI ---

    if (!analysisIdFromBody) {
      console.error("[API_ANALYZE_PCAP] No analysis ID provided in the request body.");
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 });
    }

    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromBody }); //

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

    const extractedPcapData = await parsePcapFileWithReadableStream(pcapFileUrl, pcapFileName);

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

    console.log(`[API_ANALYZE_PCAP] Data prepared for AI model for analysisId: ${analysisIdFromBody}, Stats:`, JSON.stringify(dataForAI.statistics, null, 2));

    // --- PERUBAHAN MULAI ---
      const { text: rawAnalysisText } = await generateText({
      model: groqProvider(modelNameFromEnv as any), // Pastikan ini sudah benar
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
    console.log(`[API_ANALYZE_PCAP] AI analysis raw response received (length: ${rawAnalysisText.length}) for analysisId: ${analysisIdFromBody}`);
    
    const cleanedJsonText = extractJsonFromString(rawAnalysisText);
    cleanedJsonTextForErrorLog = cleanedJsonText; 

    if (!cleanedJsonText) {
        console.error(`[API_ANALYZE_PCAP] AI response was empty or unrecoverable after cleaning for analysisId: ${analysisIdFromBody}. Raw text was:`, rawAnalysisText);
        throw new Error("AI returned empty or unrecoverable data after cleaning attempts.");
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
    
    // --- PERUBAHAN MULAI ---
    if (error instanceof Error && (error.name === 'AI_LoadAPIKeyError' || error.message.includes("API key") || error.message.includes("authentication"))) {
        return NextResponse.json({ error: "AI Provider (Groq) API key is missing, invalid, or not authorized. Please check server configuration and Groq account status.", details: error.message }, { status: 500 });
    }
    // --- PERUBAHAN SELESAI ---
    if (error instanceof SyntaxError) { 
        console.error(`[API_ANALYZE_PCAP] JSON Parsing Error. Original AI text was (first 500 chars):`, rawAnalysisTextForErrorLog?.substring(0, 500));
        console.error(`[API_ANALYZE_PCAP] JSON Parsing Error. Cleaned text attempted for parse was (first 500 chars):`, cleanedJsonTextForErrorLog?.substring(0, 500));
        return NextResponse.json({ error: "Failed to parse AI response. The AI response was not valid JSON even after cleaning attempts.", details: errorMessage }, { status: 500 });
    }

    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : "No stack available" }, { status: 500 });
  }
}
