import { type NextRequest, NextResponse } from "next/server";
import db from "@/lib/neon-db";
import PcapParser from 'pcap-parser';
import { Readable } from 'stream';

// Fungsi parsing PCAP (adaptasi dari yang sudah kita buat untuk AI Insight)
// Anda HARUS MENGEMBANGKAN INI SECARA DETAIL untuk parsing yang akurat
async function parsePcapForPacketDisplay(fileUrl: string, fileName: string): Promise<{ packets: any[], connections: any[] }> {
  console.log(`[API_GET_PACKET_DATA] Parsing PCAP for Packet Display: ${fileName} from ${fileUrl}`);
  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`Failed to download PCAP file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = PcapParser.parse(readablePcapStream);

  const parsedPackets: any[] = [];
  let packetCounter = 0;
  const MAX_PACKETS_FOR_UI_DISPLAY = 500;
  let promiseResolved = false;

  const connectionMap = new Map<string, any>();


  return new Promise((resolve, reject) => {
    const resolveOnce = (data: { packets: any[], connections: any[] }) => {
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

      let sourceIp = "N/A";
      let destIp = "N/A";
      let sourcePort: number | undefined;
      let destPort: number | undefined;
      let protocol = "UNKNOWN";
      let info = "Raw Data";
      let flags: string[] = [];
      let tcpSeq: number | undefined;
      let tcpAck: number | undefined;
      let windowSize: number | undefined;
      let ttl: number | undefined;
      let isError = false; 
      let errorType: string | undefined;
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, Length: packet.header.capturedLength }};
      let hexDump : string[] = [];

      try { // Awal blok try untuk parsing paket individual
          if (packet.data && packet.data.length >= 14) { 
              detailedInfo["Ethernet II"] = { Source: "xx:xx:xx:xx:xx:xx", Destination: "yy:yy:yy:yy:yy:yy"}; 
              const etherType = packet.data.readUInt16BE(12);
              if (etherType === 0x0800) { 
                  protocol = "IPv4"; 
                  if (packet.data.length >= 14 + 20) { 
                      const ipHeaderStart = 14;
                      const ipHeaderIHL = (packet.data[ipHeaderStart] & 0x0F);
                      const ipHeaderLength = ipHeaderIHL * 4;
                      
                      if (packet.data.length >= ipHeaderStart + ipHeaderLength) {
                          const ipHeader = packet.data.slice(ipHeaderStart, ipHeaderStart + ipHeaderLength);
                          sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                          destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                          ttl = ipHeader[8];
                          const ipProtocolField = ipHeader[9];
                          detailedInfo["IPv4"] = { Source: sourceIp, Destination: destIp, TTL: ttl, Protocol: ipProtocolField };
                          
                          const transportHeaderStart = ipHeaderStart + ipHeaderLength;

                          if (ipProtocolField === 6) { 
                              protocol = "TCP";
                              if (packet.data.length >= transportHeaderStart + 20) { 
                                  const tcpHeader = packet.data.slice(transportHeaderStart, transportHeaderStart + 20);
                                  sourcePort = tcpHeader.readUInt16BE(0);
                                  destPort = tcpHeader.readUInt16BE(2);
                                  tcpSeq = tcpHeader.readUInt32BE(4);
                                  tcpAck = tcpHeader.readUInt32BE(8);
                                  const flagsByte = tcpHeader[13];
                                  if (flagsByte & 0x01) flags.push("FIN");
                                  if (flagsByte & 0x02) flags.push("SYN");
                                  if (flagsByte & 0x04) flags.push("RST");
                                  if (flagsByte & 0x08) flags.push("PSH");
                                  if (flagsByte & 0x10) flags.push("ACK");
                                  if (flagsByte & 0x20) flags.push("URG");
                                  windowSize = tcpHeader.readUInt16BE(14);
                                  info = flags.length > 0 ? flags.join(", ") : "TCP Segment";
                                  detailedInfo["TCP"] = { SourcePort: sourcePort, DestinationPort: destPort, Seq: tcpSeq, Ack: tcpAck, Flags: flags.join(', '), Window: windowSize };
                              }
                          } else if (ipProtocolField === 17) { 
                              protocol = "UDP";
                               if (packet.data.length >= transportHeaderStart + 8) { 
                                  const udpHeader = packet.data.slice(transportHeaderStart, transportHeaderStart + 8);
                                  sourcePort = udpHeader.readUInt16BE(0);
                                  destPort = udpHeader.readUInt16BE(2);
                                  info = `UDP, Src Port: ${sourcePort}, Dst Port: ${destPort}`;
                                  detailedInfo["UDP"] = { SourcePort: sourcePort, DestinationPort: destPort, Length: udpHeader.readUInt16BE(4) };
                               }
                          } else if (ipProtocolField === 1) {
                              protocol = "ICMP";
                              info = "ICMP Packet"; 
                              detailedInfo["ICMP"] = { Type: "N/A", Code: "N/A" };
                          } else {
                              protocol = `IPProto-${ipProtocolField}`;
                              info = `IP Protocol ${ipProtocolField}`;
                          }
                      }
                  } else if (etherType === 0x86DD) {
                     protocol = "IPv6";
                     info = "IPv6 Packet";
                  } else if (etherType === 0x0806) {
                     protocol = "ARP";
                     info = "ARP Packet";
                  }
              }
              const maxHexDumpBytes = 64;
              const dataToDump = packet.data.slice(0, Math.min(packet.data.length, maxHexDumpBytes));
              for (let i = 0; i < dataToDump.length; i += 16) {
                  const slice = dataToDump.slice(i, i + 16);
                  const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || '';
                  const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
                  hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`);
              }
      } catch (e: any) { // Awal blok catch untuk parsing paket individual
          console.warn(`[API_GET_PACKET_DATA] Error decoding individual packet ${packetCounter}: ${e.message}`);
          info = `Error decoding: ${e.message}`;
          isError = true;
          errorType = "DecodingError";
      } // <-- PERBAIKAN: Kurung kurawal penutup untuk blok try di atas ditambahkan di sini

      const finalPacketData = {
        id: packetCounter,
        timestamp: new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000).toISOString(),
        sourceIp,
        sourcePort,
        destIp,
        destPort,
        protocol,
        length: packet.header.capturedLength,
        info,
        flags,
        tcpSeq,
        tcpAck,
        windowSize,
        ttl,
        isError,
        errorType,
        hexDump,
        detailedInfo
      };
      parsedPackets.push(finalPacketData);

      if ((protocol === "TCP" || protocol === "UDP") && sourcePort && destPort && sourceIp !== "N/A" && destIp !== "N/A") {
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`;
          const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`;
          const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd;

          if (!connectionMap.has(connId)) {
              connectionMap.set(connId, {
                  id: connId, sourceIp, sourcePort, destIp, destPort, protocol,
                  state: "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp,
                  hasErrors: isError, errorTypes: isError && errorType ? [errorType] : []
              });
          } else {
              const conn = connectionMap.get(connId);
              conn.packets.push(packetCounter);
              conn.endTime = finalPacketData.timestamp;
              if (isError) conn.hasErrors = true;
              if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType);
              if (protocol === "TCP" && flags.includes("RST")) conn.state = "RESET";
              else if (protocol === "TCP" && flags.includes("FIN")) conn.state = "CLOSING";
          }
      }

      if (packetCounter >= MAX_PACKETS_FOR_UI_DISPLAY) {
        console.warn(`[API_GET_PACKET_DATA] Reached packet display limit: ${MAX_PACKETS_FOR_UI_DISPLAY}`);
        if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
        }
        generateAndResolveConnections();
        return; 
      }
    }); // Akhir parser.on('packet')
    
    const generateAndResolveConnections = () => {
        const connections = Array.from(connectionMap.values());
        console.log(`[API_GET_PACKET_DATA] Resolving with ${parsedPackets.length} packets and ${connections.length} connections.`);
        resolveOnce({ packets: parsedPackets, connections });
    };
    
    parser.on('end', () => {
      console.log(`[API_GET_PACKET_DATA] Finished parsing PCAP stream. Total packets: ${packetCounter}`);
      generateAndResolveConnections();
    });

    parser.on('error', (err: Error) => {
      console.error(`[API_GET_PACKET_DATA] Error parsing PCAP stream:`, err);
      rejectOnce(new Error(`Error parsing PCAP stream: ${err.message}`));
    });
  }); // Akhir new Promise
} // Akhir outer try di parsePcapForPacketDisplay

// --- Sisa kode (OpenRouter client, extractJsonFromString, dan fungsi POST handler) ---
// Tetap sama seperti versi sebelumnya.

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

export async function GET(request: NextRequest, { params }: { params: { analysisId: string } }) { // Nama parameter analysisId di GET
  try {
    const analysisIdFromParams = params.analysisId; // Mengambil analysisId dari params
    if (!analysisIdFromParams) {
      return NextResponse.json({ error: "Analysis ID is required in path" }, { status: 400 });
    }

    console.log(`[API_GET_PACKET_DATA] Request received for analysisId: ${analysisIdFromParams}`);
    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromParams });

    if (!pcapRecord || !pcapRecord.blobUrl) {
      console.error(`[API_GET_PACKET_DATA] PCAP file or blobUrl not found for analysisId: ${analysisIdFromParams}`);
      return NextResponse.json({ error: "PCAP file not found for this analysis" }, { status: 404 });
    }

    const pcapData = await parsePcapForPacketDisplay(pcapRecord.blobUrl, pcapRecord.originalName);

    return NextResponse.json({ success: true, ...pcapData });

  } catch (error) {
    console.error("[API_GET_PACKET_DATA] Error fetching packet data:", error);
    const errorMessage = error instanceof Error ? error.message : "Failed to fetch packet data";
    return NextResponse.json({ success: false, error: errorMessage, details: error instanceof Error ? error.stack : "No stack available" }, { status: 500 });
  }
}
