import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
// import { list, head } from "@vercel/blob"; // head tidak digunakan di revisi ini, list bisa jika path tidak pasti
import db from "@/lib/neon-db"; //

// --- Placeholder untuk fungsi parsing PCAP ---
// Anda HARUS mengimplementasikan fungsi ini menggunakan library parsing PCAP.
// Contoh ini hanya mengembalikan data mock yang diacak agar berbeda tiap file.
async function parsePcapFile(fileUrl: string, fileName: string): Promise<any> {
  console.log(`[PARSE_PCAP_PLACEHOLDER] Attempting to "parse" PCAP file from URL: ${fileUrl} (File: ${fileName})`);

  // Simulasi ekstraksi data yang berbeda untuk setiap file
  // Ini BUKAN parsing PCAP yang sebenarnya.
  const randomFactor = Math.random();
  const totalPackets = Math.floor(randomFactor * 15000) + 5000; // antara 5000 dan 20000
  const tcpPackets = Math.floor(totalPackets * (0.4 + randomFactor * 0.3)); // 40-70% TCP
  const udpPackets = Math.floor(totalPackets * (0.1 + randomFactor * 0.2)); // 10-30% UDP
  const httpPackets = Math.floor(tcpPackets * (0.05 + randomFactor * 0.1)); // 5-15% dari TCP adalah HTTP
  const dnsPackets = Math.floor(udpPackets * (0.1 + randomFactor * 0.15)); // 10-25% dari UDP adalah DNS

  return {
    statistics: {
      totalPackets: totalPackets,
      protocols: {
        TCP: tcpPackets,
        UDP: udpPackets,
        HTTP: httpPackets,
        DNS: dnsPackets,
        ICMP: Math.floor(totalPackets * (0.01 + randomFactor * 0.04)), // 1-5% ICMP
      },
      topSources: [`192.168.1.${Math.floor(randomFactor * 100) + 10}`, `10.0.1.${Math.floor(randomFactor * 50) + 1}`],
      topDestinations: [`${Math.floor(randomFactor * 200 + 1)}.${Math.floor(randomFactor * 255)}.${Math.floor(randomFactor * 255)}.100`, `8.8.4.4`],
      anomalyScore: Math.floor(randomFactor * 70) + 10, // Skor anomali antara 10 dan 80
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
    // Informasi lain yang relevan untuk AI
    potentialThreatsIdentified: randomFactor > 0.7 ? ["Unusual outbound connection to rare IP", "High number of DNS queries to new domains"] : ["No immediate high-priority threats detected"],
    dataExfiltrationSigns: randomFactor > 0.85 ? "Possible data exfiltration pattern detected via DNS lookups to multiple subdomains." : "No clear signs of data exfiltration.",
  };
}
// --- Akhir dari placeholder ---

export async function POST(request: NextRequest) {
  try {
    const { analysisId } = await request.json();
    console.log(`[API_ANALYZE_PCAP] Received request for analysisId: ${analysisId}`);

    if (!analysisId) {
      console.error("[API_ANALYZE_PCAP] No analysis ID provided");
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 });
    }

    // 1. Dapatkan informasi file PCAP dari database
    const pcapRecord = await db.pcapFile.findUnique({ analysisId }); //

    if (!pcapRecord) {
      console.error(`[API_ANALYZE_PCAP] PCAP record not found in DB for analysisId: ${analysisId}`);
      return NextResponse.json({ error: "PCAP file metadata not found for this analysis" }, { status: 404 });
    }
    if (!pcapRecord.blobUrl) {
      console.error(`[API_ANALYZE_PCAP] PCAP record found, but blobUrl is missing for analysisId: ${analysisId}`);
      return NextResponse.json({ error: "PCAP file URL not found for this analysis" }, { status: 404 });
    }
    
    const pcapFileUrl = pcapRecord.blobUrl;
    const pcapFileName = pcapRecord.originalName;
    const pcapFileSize = pcapRecord.size;

    console.log(`[API_ANALYZE_PCAP] Analyzing PCAP: ${pcapFileName} (URL: ${pcapFileUrl}, Size: ${pcapFileSize} bytes) for analysisId: ${analysisId}`);

    // 2. Parse file PCAP (GANTI DENGAN IMPLEMENTASI NYATA)
    // parsePcapFile akan mengunduh file dari pcapFileUrl dan memprosesnya.
    const extractedPcapData = await parsePcapFile(pcapFileUrl, pcapFileName); //

    if (!extractedPcapData) {
        console.error(`[API_ANALYZE_PCAP] Failed to parse PCAP data for analysisId: ${analysisId}`);
        return NextResponse.json({ error: "Failed to parse PCAP file data." }, { status: 500 });
    }

    const dataForAI = {
      analysisId,
      fileName: pcapFileName,
      fileSize: pcapFileSize,
      ...extractedPcapData,
    };

    console.log(`[API_ANALYZE_PCAP] Data prepared for AI model for analysisId: ${analysisId}`, dataForAI.statistics);


    // 3. Gunakan AI untuk menganalisis data yang diekstrak
    const { text: analysis } = await generateText({
      model: openai("gpt-4o"),
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
            - id: a unique string for this finding
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
        Ensure all string values within the JSON are properly escaped.
      `,
    });

    console.log(`[API_ANALYZE_PCAP] AI analysis raw response received for analysisId: ${analysisId}`);
    const aiAnalysis = JSON.parse(analysis);
    console.log(`[API_ANALYZE_PCAP] AI analysis parsed successfully for analysisId: ${analysisId}`);

    return NextResponse.json({
      success: true,
      analysis: aiAnalysis,
    });

  } catch (error) {
    console.error(`[API_ANALYZE_PCAP] Error analyzing packet data for analysisId: ${request.url.split('=').pop()}:`, error);
    const errorMessage = error instanceof Error ? error.message : "Failed to analyze packet data";
    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : undefined }, { status: 500 });
  }
}
