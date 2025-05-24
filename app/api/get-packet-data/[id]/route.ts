import { type NextRequest, NextResponse } from "next/server";
import db from "@/lib/neon-db";
import PcapParser from 'pcap-parser';
import { Readable } from 'stream';

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
          if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
          resolve(data);
        }
    };
    const rejectOnce = (error: Error) => {
        if (!promiseResolved) {
          promiseResolved = true;
          if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
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
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, CapturedLength: packet.header.capturedLength, OriginalLength: packet.header.originalLength, Timestamp: new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000).toISOString() }};
      let hexDump : string[] = [];

      try { // Awal blok try untuk parsing paket individual
          if (packet.data && packet.data.length >= 14) { 
              detailedInfo["Ethernet II"] = { EtherType: `0x${packet.data.readUInt16BE(12).toString(16)}`}; 
              const etherType = packet.data.readUInt16BE(12);
              if (etherType === 0x0800) { // IPv4
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
                          detailedInfo["IPv4"] = { 
                              Version: 4, HeaderLength: ipHeaderLength, TTL: ttl, 
                              Protocol: ipProtocolField, SourceAddress: sourceIp, DestinationAddress: destIp,
                              TotalLength: ipHeader.readUInt16BE(2), Identification: `0x${ipHeader.readUInt16BE(4).toString(16)}`
                          };
                          
                          info = `IPv4 ${sourceIp} -> ${destIp}`;
                          const transportHeaderStart = ipHeaderStart + ipHeaderLength;
                          let transportProtocolName = `IPProto_${ipProtocolField}`;

                          if (ipProtocolField === 1) { 
                              protocol = "ICMP";
                              transportProtocolName = "ICMP";
                              info += ` (ICMP)`;
                              if (packet.data.length >= transportHeaderStart + 4) {
                                  const icmpType = packet.data[transportHeaderStart];
                                  const icmpCode = packet.data[transportHeaderStart + 1];
                                  detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode };
                                  info += ` Type ${icmpType} Code ${icmpCode}`;
                              }
                          } else if (ipProtocolField === 6) { 
                              protocol = "TCP";
                              transportProtocolName = "TCP";
                              if (packet.data.length >= transportHeaderStart + 20) { 
                                  const tcpHeaderBasic = packet.data.slice(transportHeaderStart, transportHeaderStart + 20);
                                  sourcePort = tcpHeaderBasic.readUInt16BE(0);
                                  destPort = tcpHeaderBasic.readUInt16BE(2);
                                  tcpSeq = tcpHeaderBasic.readUInt32BE(4);
                                  tcpAck = tcpHeaderBasic.readUInt32BE(8);
                                  const dataOffsetByte = tcpHeaderBasic[12]; 
                                  const tcpHeaderLength = ((dataOffsetByte & 0xF0) >> 4) * 4;
                                  const flagsByte = tcpHeaderBasic[13];
                                  
                                  flags = [];
                                  if (flagsByte & 0x01) flags.push("FIN");
                                  if (flagsByte & 0x02) flags.push("SYN");
                                  if (flagsByte & 0x04) flags.push("RST");
                                  if (flagsByte & 0x08) flags.push("PSH");
                                  if (flagsByte & 0x10) flags.push("ACK");
                                  if (flagsByte & 0x20) flags.push("URG");
                                  
                                  windowSize = tcpHeaderBasic.readUInt16BE(14);
                                  info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq} Ack=${tcpAck} Win=${windowSize} Len=${packet.header.capturedLength - (transportHeaderStart + tcpHeaderLength)}`;
                                  detailedInfo["TCP"] = { 
                                      SourcePort: sourcePort, DestinationPort: destPort, 
                                      SequenceNumber: tcpSeq, AckNumber: tcpAck, HeaderLength: tcpHeaderLength,
                                      Flags: flags.join(', '), WindowSize: windowSize,
                                      Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`,
                                      UrgentPointer: tcpHeaderBasic.readUInt16BE(18)
                                  };
                                  if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; }
                              } else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; }
                          } else if (ipProtocolField === 17) { 
                              protocol = "UDP";
                              transportProtocolName = "UDP";
                               if (packet.data.length >= transportHeaderStart + 8) { 
                                  const udpHeader = packet.data.slice(transportHeaderStart, transportHeaderStart + 8);
                                  sourcePort = udpHeader.readUInt16BE(0);
                                  destPort = udpHeader.readUInt16BE(2);
                                  const udpLength = udpHeader.readUInt16BE(4);
                                  info = `${sourcePort} → ${destPort} Len=${udpLength - 8}`;
                                  detailedInfo["UDP"] = { 
                                      SourcePort: sourcePort, DestinationPort: destPort, 
                                      Length: udpLength, Checksum: `0x${udpHeader.readUInt16BE(6).toString(16)}`
                                  };
                               } else { info = "UDP (Truncated Header)"; isError = true; errorType = "TruncatedUDP"; }
                          } else {
                              protocol = transportProtocolName;
                              info = `IP Protocol ${ipProtocolField}`;
                          }
                      } else { info = "IPv4 (Truncated IP Header)"; isError = true; errorType = "TruncatedIP"; protocol = "IPv4"; }
                  } else { info = "IPv4 (Short Packet)"; isError = true; errorType = "ShortIPPacket"; protocol = "IPv4"; }
              } else if (etherType === 0x86DD) { 
                 protocol = "IPv6";
                 info = "IPv6 Packet (detail parsing not fully implemented)";
                 detailedInfo["IPv6"] = { Payload: "Further parsing needed" };
              } else if (etherType === 0x0806) { 
                 protocol = "ARP";
                 info = "ARP Packet (detail parsing not fully implemented)";
                 detailedInfo["ARP"] = { Payload: "Further parsing needed" };
              } else {
                 protocol = `EtherType_0x${etherType.toString(16)}`;
                 info = `EtherType 0x${etherType.toString(16)}`;
              }
          } // Akhir if (packet.data && packet.data.length >= 14)

          const maxHexDumpBytes = 64;
          const dataBufferForDump = packet.data || Buffer.alloc(0);
          const dataToDump = dataBufferForDump.slice(0, Math.min(dataBufferForDump.length, maxHexDumpBytes));
          for (let i = 0; i < dataToDump.length; i += 16) {
              const slice = dataToDump.slice(i, i + 16);
              const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || '';
              const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
              hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`);
          } // Akhir for loop untuk hexDump
      } catch (e: any) { // Ini adalah catch untuk try parsing paket individual
          console.warn(`[API_GET_PACKET_DATA] Error decoding individual packet ${packetCounter}: ${e.message}`);
          info = `Error decoding: ${e.message}`;
          isError = true;
          errorType = "DecodingError";
      } // Ini adalah penutup 'try' yang benar

      const finalPacketData = {
        id: packetCounter,
        timestamp: new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000).toISOString(),
        sourceIp, sourcePort, destIp, destPort, protocol,
        length: packet.header.capturedLength, info, flags,
        tcpSeq, tcpAck, windowSize, ttl,
        isError, errorType, hexDump, detailedInfo
      };
      parsedPackets.push(finalPacketData);

      if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") {
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`;
          const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`;
          const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd;

          if (!connectionMap.has(connId)) {
              connectionMap.set(connId, {
                  id: connId, sourceIp, sourcePort, destIp, destPort, protocol,
                  state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", 
                  packets: [packetCounter], startTime: finalPacketData.timestamp,
                  hasErrors: isError, errorTypes: isError && errorType ? [errorType] : []
              });
          } else {
              const conn = connectionMap.get(connId);
              conn.packets.push(packetCounter);
              conn.endTime = finalPacketData.timestamp;
              if (isError && !conn.hasErrors) conn.hasErrors = true;
              if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType);
              
              if (protocol === "TCP") {
                if (flags.includes("RST")) conn.state = "RESET";
                else if (flags.includes("FIN") && flags.includes("ACK")) conn.state = "FIN_ACK";
                else if (flags.includes("FIN") && conn.state !== "RESET") conn.state = "FIN_WAIT";
                else if (flags.includes("SYN") && flags.includes("ACK") && conn.state === "SYN_SENT") conn.state = "ESTABLISHED";
                else if (flags.includes("SYN") && conn.state !== "ESTABLISHED" && conn.state !== "RESET") conn.state = "SYN_SENT";
              }
          }
      }

      if (packetCounter >= MAX_PACKETS_FOR_UI_DISPLAY) {
        console.warn(`[API_GET_PACKET_DATA] Reached packet display limit: ${MAX_PACKETS_FOR_UI_DISPLAY}`);
        generateAndResolveConnections(); 
      }
    }); // Akhir parser.on('packet')
    
    const generateAndResolveConnections = () => {
        if (promiseResolved) return; 
        const connections = Array.from(connectionMap.values());
        console.log(`[API_GET_PACKET_DATA] Resolving with ${parsedPackets.length} packets and ${connections.length} connections.`);
        resolveOnce({ packets: parsedPackets, connections });
    };
    
    parser.on('end', () => {
      if (promiseResolved) return;
      console.log(`[API_GET_PACKET_DATA] Finished parsing PCAP stream. Total packets: ${packetCounter}`);
      generateAndResolveConnections();
    });

    parser.on('error', (err: Error) => {
      if (promiseResolved) return;
      console.error(`[API_GET_PACKET_DATA] Error parsing PCAP stream:`, err);
      rejectOnce(new Error(`Error parsing PCAP stream: ${err.message}`));
    });
  }); // Akhir new Promise
} // Akhir fungsi parsePcapForPacketDisplay


export async function GET(request: NextRequest, { params }: { params: { analysisId: string } }) {
  try {
    const analysisIdFromParams = params.analysisId;
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
