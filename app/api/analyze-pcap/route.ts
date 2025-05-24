import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai"; // Menggunakan factory dari @ai-sdk/openai
import db from "@/lib/neon-db";
import PcapParser from 'pcap-parser'; // Impor pcap-parser
// import { Buffer } from 'buffer'; // Mungkin diperlukan jika Buffer tidak tersedia global di environment

// --- Implementasi Awal parsePcapFile dengan pcap-parser ---
async function parsePcapFile(fileUrl: string, fileName: string): Promise<any> {
  console.log(`[PARSE_PCAP_ACTUAL] Attempting to parse PCAP from URL: ${fileUrl} (File: ${fileName})`);
  try {
    const pcapResponse = await fetch(fileUrl);
    if (!pcapResponse.ok || !pcapResponse.body) {
      throw new Error(`Failed to download PCAP file: ${pcapResponse.statusText}`);
    }
    const arrayBuffer = await pcapResponse.arrayBuffer();
    const pcapBuffer = Buffer.from(arrayBuffer); // Konversi ArrayBuffer ke Buffer Node.js

    const parser = PcapParser.parse(pcapBuffer);
    
    let packetCount = 0;
    const protocolStats: { [key: string]: number } = {};
    const samplePacketsForAI: Array<any> = [];
    const MAX_SAMPLES_FOR_AI = 10; 
    const MAX_PACKETS_TO_PROCESS_FOR_STATS = 10000; 

    const ipCounts: { [ip: string]: { sent: number, received: number, sentBytes: number, receivedBytes: number } } = {};

    return new Promise((resolve, reject) => {
      parser.on('packet', (packet: any) => { 
        packetCount++;
        
        let sourceIp = "N/A";
        let destIp = "N/A";
        let protocolName = "UNKNOWN";
        let packetLength = packet.header.capturedLength;
        let packetInfo = `Raw packet data, length ${packetLength}`; // Info default

        // Contoh parsing dasar header Ethernet II -> IPv4 -> TCP/UDP/ICMP
        // Ini adalah contoh yang disederhanakan dan mungkin perlu penyesuaian mendalam.
        // Anda perlu mempelajari struktur output dari 'pcap-parser' dan byte offset yang benar.
        if (packet.data && packet.data.length >= 34) { // Min length for Eth + IPv4 header
            const ethType = packet.data.readUInt16BE(12); // EtherType field
            if (ethType === 0x0800) { // IPv4
                const ipHeaderStart = 14;
                const ipHeader = packet.data.slice(ipHeaderStart);
                
                if (ipHeader.length >= 20) { // Min IPv4 header length
                    const ipVersion = (ipHeader[0] >> 4) & 0x0F;
                    if (ipVersion === 4) {
                        const ipProtocolField = ipHeader[9];
                        sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                        destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                        packetInfo = `IPv4 ${sourceIp} -> ${destIp}`;

                        if (ipProtocolField === 1) {
                            protocolName = 'ICMP';
                            packetInfo += ` ICMP`;
                        } else if (ipProtocolField === 6) {
                            protocolName = 'TCP';
                            packetInfo += ` TCP`;
                            // Anda bisa menambahkan parsing port TCP di sini
                        } else if (ipProtocolField === 17) {
                            protocolName = 'UDP';
                            packetInfo += ` UDP`;
                            // Anda bisa menambahkan parsing port UDP di sini
                        }
                    }
                }
            } else if (ethType === 0x86DD) { // IPv6
                protocolName = 'IPv6'; // Perlu parsing IPv6 lebih lanjut
                packetInfo = `IPv6 packet`;
            }
        }
        
        protocolStats[protocolName] = (protocolStats[protocolName] || 0) + 1;

        if (sourceIp !== "N/A") {
            ipCounts[sourceIp] = ipCounts[sourceIp] || { sent: 0, received: 0, sentBytes: 0, receivedBytes: 0 };
            ipCounts[sourceIp].sent++;
            ipCounts[sourceIp].sentBytes += packetLength;
        }
        if (destIp !== "N/A") {
            ipCounts[destIp] = ipCounts[destIp] || { sent: 0, received: 0, sentBytes: 0, receivedBytes: 0 };
            ipCounts[destIp].received++;
            ipCounts[destIp].receivedBytes += packetLength;
        }

        if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI) {
          samplePacketsForAI.push({
            timestamp: new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000).toISOString(),
            sourceIp: sourceIp,
            destIp: destIp,
            protocol: protocolName,
            length: packetLength,
            info: packetInfo,
          });
        }

        if (packetCount >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) {
          console.warn(`[PARSE_PCAP_ACTUAL] Reached packet processing limit for stats: ${MAX_PACKETS_TO_PROCESS_FOR_STATS} for file ${fileName}`);
          parser.eventNames().forEach(event => parser.removeAllListeners(event as any));
          
          const topTalkers = Object.entries(ipCounts)
            .map(([ip, data]) => ({ ip, packets: data.sent + data.received, bytes: data.sentBytes + data.receivedBytes }))
            .sort((a, b) => b.packets - a.packets)
            .slice(0, 5);

          resolve({
            statistics: {
              totalPackets: packetCount, // Ini adalah jumlah paket yang diproses sejauh ini
              analyzedForStatsPackets: Math.min(packetCount, MAX_PACKETS_TO_PROCESS_FOR_STATS),
              protocols: protocolStats,
              topTalkers: topTalkers,
              anomalyScore: Math.floor(Math.random() * 30) + 20, // Ganti dengan logika anomali nyata
            },
            samplePackets: samplePacketsForAI,
            potentialThreatsIdentified: ["Based on preliminary scan..."],
            dataExfiltrationSigns: "Checking for exfiltration patterns...",
          });
        }
      });

      parser.on('end', () => {
        console.log(`[PARSE_PCAP_ACTUAL] Finished parsing. Total packets processed: ${packetCount} for file: ${fileName}`);
        
        const topTalkers = Object.entries(ipCounts)
          .map(([ip, data]) => ({ ip, packets: data.sent + data.received, bytes: data.sentBytes + data.receivedBytes }))
          .sort((a, b) => b.packets - a.packets)
          .slice(0, 5);
          
        resolve({
          statistics: {
            totalPackets: packetCount,
            analyzedForStatsPackets: packetCount,
            protocols: protocolStats,
            topTalkers: topTalkers,
            anomalyScore: Math.floor(Math.random() * 30) + 20, 
          },
          samplePackets: samplePacketsForAI,
          potentialThreatsIdentified: Object.keys(protocolStats).length > 1 ? ["Diverse protocol usage noted"] : ["Limited protocol diversity"],
          dataExfiltrationSigns: packetCount > 500 ? "Moderate traffic volume observed" : "Low traffic volume",
        });
      });

      parser.on('error', (err: Error) => {
        console.error(`[PARSE_PCAP_ACTUAL] Error parsing PCAP file ${fileName}:`, err);
        reject(new Error(`Error parsing PCAP file: ${err.message}`));
      });

    } catch (error) {
      console.error(`[PARSE_PCAP_ACTUAL] Outer error in parsePcapFile for ${fileName}:`, error);
      return Promise.reject(error instanceof Error ? error : new Error("Unknown error during PCAP processing"));
    }
  }
}
// --- Akhir dari implementasi awal parsePcapFile ---


const openRouterApiKey = process.env.OPENROUTER_API_KEY;
const openRouterBaseURL = process.env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1";
const modelNameFromEnv = process.env.OPENROUTER_MODEL_NAME || "mistralai/mistral-7b-instruct";

let openRouterProvider: ReturnType<typeof createOpenAI> | null = null;

if (openRouterApiKey && openRouterApiKey.trim() !== "") {
  openRouterProvider = createOpenAI({
    apiKey: openRouterApiKey,
    baseURL: openRouterBaseURL,
  });
  console.log("[API_ANALYZE_PCAP_CONFIG] OpenRouter provider configured using createOpenAI from @ai-sdk/openai.");
} else {
  console.error("[CRITICAL_CONFIG_ERROR] OPENROUTER_API_KEY environment variable is missing or empty. AI features will be disabled.");
}

// Fungsi untuk membersihkan string JSON dari markdown backticks
function extractJsonFromString(text: string): string | null {
    console.log("[EXTRACT_JSON] Original AI text length:", text.length);
    // Mencari ```json ... ``` atau ``` ... ```
    const regex = /```(?:json)?\s*([\s\S]*?)\s*```/;
    const match = text.match(regex);
  
    if (match && match[1]) {
      console.log("[EXTRACT_JSON] JSON found inside markdown backticks.");
      return match[1].trim();
    }
    
    // Jika tidak ada backticks, coba cari '{' pertama dan '}' terakhir
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      const potentialJson = text.substring(firstBrace, lastBrace + 1);
      try {
          JSON.parse(potentialJson); // Validasi sederhana
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
  let rawAnalysisTextForErrorLog: string | undefined; // Untuk logging jika JSON.parse gagal
  let cleanedJsonTextForErrorLog: string | undefined; // Untuk logging jika JSON.parse gagal

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

    const extractedPcapData = await parsePcapFile(pcapFileUrl, pcapFileName);

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

    console.log(`[API_ANALYZE_PCAP] Data prepared for AI model for analysisId: ${analysisIdFromBody}`);

    const { text: rawAnalysisText } = await generateText({
      model: openRouterProvider(modelNameFromEnv as any),
      prompt: `
        You are a network security expert analyzing PCAP data.
        The data is from file: "${dataForAI.fileName}" (size: ${dataForAI.fileSize} bytes, analysis ID: ${dataForAI.analysisId}).
        
        Key Extracted PCAP Data:
        - Overall Statistics: ${JSON.stringify(dataForAI.statistics, null, 2)}
        - Sample Packets (if any): ${JSON.stringify(dataForAI.samplePackets, null, 2)}
        - Preliminary Scan Results (if any): 
          - Potential Threats: ${JSON.stringify(dataForAI.potentialThreatsIdentified)}
          - Data Exfiltration Signs: ${dataForAI.dataExfiltrationSigns}

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
            - relatedPackets: (optional) reference relevant sample packet indices if applicable (e.g., [0, 1])
        4. Identify up to 3-5 Indicators of Compromise (IOCs) if any are strongly suggested by the data. For each IOC:
            - type: (ip, domain, url, hash)
            - value: the IOC value
            - context: why this is an IOC based on the data
            - confidence: (0-100)
        5. Suggest 2-3 general recommendations for improving security based on patterns seen. For each recommendation:
            - title
            - description
            - priority: (low, medium, high)
        6. Create a brief timeline of up to 3-5 most significant events if discernible from the provided data (use timestamps from sample packets if relevant). For each timeline event:
            - time: (ISO string or relative time like "Packet Sample 0 Timestamp")
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

    rawAnalysisTextForErrorLog = rawAnalysisText; // Simpan untuk logging jika parse gagal
    console.log(`[API_ANALYZE_PCAP] AI analysis raw response received (length: ${rawAnalysisText.length}) for analysisId: ${analysisIdFromBody}`);
    
    const cleanedJsonText = extractJsonFromString(rawAnalysisText);
    cleanedJsonTextForErrorLog = cleanedJsonText; // Simpan untuk logging

    if (!cleanedJsonText) {
        console.error(`[API_ANALYZE_PCAP] Failed to extract valid JSON from AI response for analysisId: ${analysisIdFromBody}. Raw text was:`, rawAnalysisText);
        throw new Error("AI returned data in an unrecoverable format or empty after cleaning.");
    }
    
    console.log(`[API_ANALYZE_PCAP] Cleaned JSON text for parsing (length: ${cleanedJsonText.length}):`, cleanedJsonText.substring(0, 200) + "..."); // Log sebagian kecil
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
