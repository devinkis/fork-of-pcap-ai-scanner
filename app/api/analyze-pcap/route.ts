import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
// Ubah cara import untuk OpenAI client
import { createOpenAI } from "ai/openai"; // Menggunakan factory dari 'ai/openai'
import db from "@/lib/neon-db";

// --- Placeholder untuk fungsi parsing PCAP ---
// Anda HARUS mengimplementasikan fungsi ini menggunakan library parsing PCAP pilihan Anda.
// Contoh ini hanya mengembalikan data mock yang diacak.
async function parsePcapFile(fileUrl: string, fileName: string): Promise<any> {
  console.log(`[PARSE_PCAP_PLACEHOLDER] Attempting to "parse" PCAP file from URL: ${fileUrl} (File: ${fileName})`);
  const randomFactor = Math.random();
  const totalPackets = Math.floor(randomFactor * 15000) + 5000;
  const tcpPackets = Math.floor(totalPackets * (0.4 + randomFactor * 0.3));
  const udpPackets = Math.floor(totalPackets * (0.1 + randomFactor * 0.2));
  const httpPackets = Math.floor(tcpPackets * (0.05 + randomFactor * 0.1));
  const dnsPackets = Math.floor(udpPackets * (0.1 + randomFactor * 0.15));

  return {
    statistics: {
      totalPackets: totalPackets,
      protocols: {
        TCP: tcpPackets,
        UDP: udpPackets,
        HTTP: httpPackets,
        DNS: dnsPackets,
        ICMP: Math.floor(totalPackets * (0.01 + randomFactor * 0.04)),
      },
      topSources: [`192.168.1.${Math.floor(randomFactor * 100) + 10}`, `10.0.1.${Math.floor(randomFactor * 50) + 1}`],
      topDestinations: [`${Math.floor(randomFactor * 200 + 1)}.${Math.floor(randomFactor * 255)}.${Math.floor(randomFactor * 255)}.100`, `8.8.4.4`],
      anomalyScore: Math.floor(randomFactor * 70) + 10,
    },
    samplePackets: [
      {
        timestamp: new Date(Date.now() - Math.floor(randomFactor * 3600000)).toISOString(),
        sourceIp: `192.168.1.${Math.floor(randomFactor * 100) + 10}`,
        destIp: "8.8.8.8",
        protocol: "DNS",
        length: Math.floor(randomFactor * 30) + 50,
        info: `Standard query 0x${Math.random().toString(16).substr(2, 4)} AAAA example-${Math.floor(randomFactor * 10)}.com`,
      },
      {
        timestamp: new Date(Date.now() - Math.floor(randomFactor * 1800000)).toISOString(),
        sourceIp: `10.0.1.${Math.floor(randomFactor * 50) + 1}`,
        destIp: `${Math.floor(randomFactor * 200 + 1)}.${Math.floor(randomFactor * 255)}.${Math.floor(randomFactor * 255)}.100`,
        protocol: "TCP",
        length: Math.floor(randomFactor * 1000) + 400,
        info: "[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 WS=256 SACK_PERM=1",
      },
    ],
    potentialThreatsIdentified: randomFactor > 0.7 ? ["Unusual outbound connection to rare IP", "High number of DNS queries to new domains"] : ["No immediate high-priority threats detected"],
    dataExfiltrationSigns: randomFactor > 0.85 ? "Possible data exfiltration pattern detected via DNS lookups to multiple subdomains." : "No clear signs of data exfiltration.",
  };
}
// --- Akhir dari placeholder ---

// Ambil konfigurasi dari environment variables
const openRouterApiKey = process.env.OPENROUTER_API_KEY;
const openRouterBaseURL = process.env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1";
const modelNameFromEnv = process.env.OPENROUTER_MODEL_NAME || "mistralai/mistral-7b-instruct"; // Model default

// Inisialisasi provider OpenRouter.
// Provider hanya akan dibuat jika API key ada.
let openRouterProvider: ReturnType<typeof createOpenAI> | null = null;

if (openRouterApiKey && openRouterApiKey.trim() !== "") {
  openRouterProvider = createOpenAI({ // Menggunakan factory createOpenAI
    apiKey: openRouterApiKey,
    baseURL: openRouterBaseURL,
  });
  console.log("[API_ANALYZE_PCAP_CONFIG] OpenRouter provider configured using createOpenAI.");
} else {
  console.error("[CRITICAL_CONFIG_ERROR] OPENROUTER_API_KEY environment variable is missing or empty. AI features will be disabled.");
}

export async function POST(request: NextRequest) {
  let analysisIdFromBody: string | undefined;
  try {
    const body = await request.json();
    analysisIdFromBody = body.analysisId;
    console.log(`[API_ANALYZE_PCAP] Received request for analysisId: ${analysisIdFromBody}`);

    if (!openRouterProvider) {
      console.error("[API_ANALYZE_PCAP] OpenRouter provider is not configured. OPENROUTER_API_KEY is likely missing or empty in environment variables.");
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

    const { text: analysis } = await generateText({
      // Gunakan provider dan nama model yang sudah dikonfigurasi
      model: openRouterProvider.chat(modelNameFromEnv as any), 
      // Alternatif jika .chat() tidak sesuai: openRouterProvider(modelNameFromEnv as any)
      // Sesuaikan berdasarkan apa yang dikembalikan oleh createOpenAI dan bagaimana Vercel AI SDK mengharapkannya
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
        Ensure all string values within the JSON are properly escaped. If you cannot provide certain fields because the data is insufficient, omit them or provide an empty array/object as appropriate for the JSON structure. If the input data is minimal or contains no clear security events, state that in the summary and provide minimal or empty arrays for findings/iocs.
      `,
    });

    console.log(`[API_ANALYZE_PCAP] AI analysis raw response received for analysisId: ${analysisIdFromBody}`);
    const aiAnalysis = JSON.parse(analysis);
    console.log(`[API_ANALYZE_PCAP] AI analysis parsed successfully for analysisId: ${analysisIdFromBody}`);

    return NextResponse.json({
      success: true,
      analysis: aiAnalysis,
    });

  } catch (error) {
    const analysisIdForLogError = analysisIdFromBody || request.nextUrl.searchParams.get('analysisId') || 'unknown';
    console.error(`[API_ANALYZE_PCAP] Error analyzing packet data for analysisId: ${analysisIdForLogError}:`, error);
    
    const errorMessage = error instanceof Error ? error.message : "An unexpected error occurred during AI analysis.";
    
    // Tangani error spesifik jika diperlukan, misal AI_APITimeoutError, AI_InvalidAPIKeyError, dll.
    // Error 'AI_LoadAPIKeyError' mungkin tidak akan muncul lagi jika createOpenAI menangani ini secara internal.
    if (error instanceof Error && (error.name === 'AI_LoadAPIKeyError' || error.message.includes("API key") || error.message.includes("authentication"))) {
        return NextResponse.json({ error: "AI Provider API key is missing, invalid, or not authorized. Please check server configuration and OpenRouter account status.", details: error.message }, { status: 500 });
    }
    if (error instanceof SyntaxError && errorMessage.includes("JSON.parse")) {
        return NextResponse.json({ error: "Failed to parse AI response. The AI might have returned an invalid JSON.", details: errorMessage }, { status: 500 });
    }

    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : "No stack available" }, { status: 500 });
  }
}
