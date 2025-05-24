import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import db from "@/lib/neon-db";
import PcapParser from 'pcap-parser'; // Library pcap-parser
import { Readable } from 'stream';    // Untuk membuat stream dari buffer

// Implementasi parsePcapFile dengan pcap-parser dan Readable.from
async function parsePcapFileWithReadableStream(fileUrl: string, fileName: string): Promise<any> {
  console.log(`[PARSE_PCAP_PARSER_STREAM] Attempting to parse PCAP from URL: ${fileUrl} (File: ${fileName})`);
  try {
    const pcapResponse = await fetch(fileUrl);
    if (!pcapResponse.ok || !pcapResponse.body) {
      throw new Error(`Failed to download PCAP file: ${pcapResponse.statusText}`);
    }
    const arrayBuffer = await pcapResponse.arrayBuffer();
    const pcapBuffer = Buffer.from(arrayBuffer);

    const readablePcapStream = Readable.from(pcapBuffer); // Buat stream
    const parser = PcapParser.parse(readablePcapStream); // Berikan stream ke parser

    let packetCounter = 0;
    const protocolGuessStats: { [key: string]: number } = {'UNKNOWN_L3': 0}; // Inisialisasi
    const samplePacketsForAI: Array<any> = [];
    const MAX_SAMPLES_FOR_AI = 10;
    const MAX_PACKETS_TO_PROCESS_FOR_STATS = 2000; // Batasi untuk performa awal
    let promiseResolved = false; // Flag untuk memastikan resolve/reject hanya dipanggil sekali

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
        if (promiseResolved) return; // Jangan proses jika promise sudah selesai

        packetCounter++;
        const packetLength = packet.header.capturedLength;
        const timestamp = new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000).toISOString();
        
        let guessedProtocol = "UNKNOWN_L3";
        let sourceIp = "N/A";
        let destIp = "N/A";
        let packetInfo = `Raw Link Layer Data (len ${packetLength})`;

        try {
            if (packet.data && packet.data.length >= 14) {
                const etherType = packet.data.readUInt16BE(12);
                if (etherType === 0x0800) { // IPv4
                    guessedProtocol = "IPv4";
                    if (packet.data.length >= 14 + 20) {
                        const ipHeader = packet.data.slice(14, 14 + 20);
                        sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                        destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                        const ipProtocolField = ipHeader[9];
                        if (ipProtocolField === 6) guessedProtocol = "TCP (over IPv4)";
                        else if (ipProtocolField === 17) guessedProtocol = "UDP (over IPv4)";
                        else if (ipProtocolField === 1) guessedProtocol = "ICMP (over IPv4)";
                        packetInfo = `IPv4 ${sourceIp} -> ${destIp}`;
                    }
                } else if (etherType === 0x86DD) guessedProtocol = "IPv6";
                else if (etherType === 0x0806) guessedProtocol = "ARP";
            }
        } catch (e: any) {
            console.warn(`[PARSE_PCAP_PARSER_STREAM] Error decoding individual packet ${packetCounter}: ${e.message}`);
        }
        protocolGuessStats[guessedProtocol] = (protocolGuessStats[guessedProtocol] || 0) + 1;

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
        }
      });

      const resolveResults = () => {
        const topProtocols = Object.entries(protocolGuessStats)
            .sort(([,a],[,b]) => b-a)
            .slice(0, 5)
            .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});

        resolveOnce({
          statistics: {
            totalPacketsInFile: packetCounter, 
            packetsProcessedForStats: packetCounter, 
            protocols: topProtocols,
            topTalkers: [{ip: "N/A (detail parsing needed)", packets: 0, bytes: 0}],
            anomalyScore: Math.floor(Math.random() * 30) + 10, 
          },
          samplePackets: samplePacketsForAI,
          potentialThreatsIdentified: ["Basic scan by pcap-parser, deeper analysis pending."],
          dataExfiltrationSigns: "Not determined from basic parsing.",
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
// --- Akhir dari implementasi parsePcapFile ---


// --- Sisa kode (OpenRouter client, extractJsonFromString, dan fungsi POST handler) ---
// Tetap sama seperti versi sebelumnya, pastikan pemanggilan fungsi parsing adalah parsePcapFileWithReadableStream.

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

    const extractedPcapData = await parsePcapFileWithReadableStream(pcapFileUrl, pcapFileName); // Menggunakan fungsi ini

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
