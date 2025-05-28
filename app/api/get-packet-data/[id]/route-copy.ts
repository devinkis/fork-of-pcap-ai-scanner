// app/api/get-packet-data/[id]/route.ts
import { type NextRequest, NextResponse } from "next/server";
import db from "@/lib/neon-db";
// const PcapParser = require('pcap-parser'); // Hapus impor lama
const PCAPNGParser = require('pcap-ng-parser'); // Impor library baru
import { Readable } from 'stream';

// Fungsi helper untuk konversi timestamp pcap-ng (jika diperlukan)
function pcapNgTimestampToDate(timestampHigh: number, timestampLow: number): Date {
  // PCAPNG timestamps are typically 64-bit, split into high and low 32-bit parts.
  // The unit is usually microseconds from epoch.
  // JavaScript's Date uses milliseconds.
  // This is a simplified approach; a more robust solution might involve BigInt
  // if timestamps are very large, but for common cases this should work.
  const seconds = timestampHigh * (2**32 / 1e6) + timestampLow / 1e6;
  return new Date(seconds * 1000);
}


async function parsePcapFileWithPcapNgParser(fileUrl: string, fileName: string): Promise<{ packets: any[], connections: any[] }> {
  console.log(`[API_GET_PACKET_DATA] Parsing PCAPNG/PCAP with pcap-ng-parser: ${fileName} from ${fileUrl}`);
  
  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`Failed to download PCAP file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = new PCAPNGParser(); // Gunakan constructor baru

  const parsedPackets: any[] = [];
  let packetCounter = 0;
  const MAX_PACKETS_FOR_UI_DISPLAY = 500; // Batas yang sama
  let promiseResolved = false;

  const connectionMap = new Map<string, any>();
  let currentInterfaceInfo: any = null; // Untuk menyimpan info interface terakhir

  return new Promise((resolve, reject) => {
    const resolveOnce = (data: { packets: any[], connections: any[] }) => {
        if (!promiseResolved) {
          promiseResolved = true;
          if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
          readablePcapStream.unpipe(parser); // Pastikan unpipe
          readablePcapStream.destroy();
          resolve(data);
        }
    };
    const rejectOnce = (error: Error) => {
        if (!promiseResolved) {
          promiseResolved = true;
          if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
          readablePcapStream.unpipe(parser); // Pastikan unpipe
          readablePcapStream.destroy();
          reject(error);
        }
    };

    readablePcapStream.pipe(parser); // Pipe stream ke parser

    parser.on('interface', (interfaceDescription: any) => {
      console.log('[API_GET_PACKET_DATA] Interface Description Block:', interfaceDescription);
      currentInterfaceInfo = interfaceDescription; // Simpan info interface
      // Anda bisa menggunakan interfaceDescription.linkLayerType jika perlu
    });
    
    parser.on('data', (parsedPcapNgPacket: any) => {
      // 'parsedPcapNgPacket' adalah blok paket dari pcap-ng-parser
      // Struktur umumnya: { type: string (e.g., 'EnhancedPacketBlock'), interfaceId: number, timestampHigh: number, timestampLow: number, data: Buffer (payload mentah paket) }
      // Beberapa blok mungkin tidak memiliki 'data', seperti 'InterfaceStatisticsBlock'
      if (promiseResolved || parsedPcapNgPacket.type !== 'EnhancedPacketBlock' || !parsedPcapNgPacket.data) {
        if (parsedPcapNgPacket.type !== 'EnhancedPacketBlock') {
            // console.log(`[API_GET_PACKET_DATA] Skipping non-packet block: ${parsedPcapNgPacket.type}`);
        }
        return;
      }

      packetCounter++;
      
      const packetDataBuffer = parsedPcapNgPacket.data; // Ini adalah buffer data paket mentah
      // Timestamp dari pcap-ng biasanya dalam microseconds, perlu konversi jika high/low terpisah
      const timestamp = pcapNgTimestampToDate(parsedPcapNgPacket.timestampHigh, parsedPcapNgPacket.timestampLow).toISOString();
      const capturedLength = parsedPcapNgPacket.capturedLength || packetDataBuffer.length; // Ambil dari blok jika ada
      const originalLength = parsedPcapNgPacket.originalPacketLength || packetDataBuffer.length;

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
      // Gunakan capturedLength dan originalLength dari parsedPcapNgPacket jika tersedia
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, CapturedLength: capturedLength, OriginalLength: originalLength, Timestamp: timestamp, InterfaceID: parsedPcapNgPacket.interfaceId }};
      if (currentInterfaceInfo && currentInterfaceInfo.id === parsedPcapNgPacket.interfaceId) {
        detailedInfo["Frame Info"].InterfaceName = currentInterfaceInfo.name || `Interface ${currentInterfaceInfo.id}`;
        detailedInfo["Frame Info"].LinkLayerType = currentInterfaceInfo.linkLayerType; // Penting untuk decoding!
      }
      let hexDump : string[] = [];

      // Link layer type, default ke Ethernet (1) jika tidak ada info interface
      const linkLayerType = (currentInterfaceInfo && currentInterfaceInfo.id === parsedPcapNgPacket.interfaceId) ? currentInterfaceInfo.linkLayerType : 1;

      try { 
          // Asumsi Link Layer adalah Ethernet (type 1) jika tidak ada info lain
          // Jika linkLayerType BUKAN Ethernet, logika decoding di bawah ini mungkin perlu disesuaikan atau dilewati
          if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >= 14) { 
              detailedInfo["Ethernet II"] = { 
                DestinationMAC: packetDataBuffer.slice(0,6).toString('hex').match(/.{1,2}/g)?.join(':'),
                SourceMAC: packetDataBuffer.slice(6,12).toString('hex').match(/.{1,2}/g)?.join(':'),
                EtherType: `0x${packetDataBuffer.readUInt16BE(12).toString(16)}`
              }; 
              const etherType = packetDataBuffer.readUInt16BE(12);

              if (etherType === 0x0800) { // IPv4
                  protocol = "IPv4"; 
                  if (packetDataBuffer.length >= 14 + 20) { 
                      const ipHeaderStart = 14;
                      const ipHeaderIHL = (packetDataBuffer[ipHeaderStart] & 0x0F);
                      const ipHeaderLength = ipHeaderIHL * 4;
                      
                      if (packetDataBuffer.length >= ipHeaderStart + ipHeaderLength) {
                          const ipHeader = packetDataBuffer.slice(ipHeaderStart, ipHeaderStart + ipHeaderLength);
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

                          if (ipProtocolField === 1) { // ICMP
                              protocol = "ICMP";
                              transportProtocolName = "ICMP";
                              info += ` (ICMP)`;
                              if (packetDataBuffer.length >= transportHeaderStart + 4) {
                                  const icmpType = packetDataBuffer[transportHeaderStart];
                                  const icmpCode = packetDataBuffer[transportHeaderStart + 1];
                                  detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode, Checksum: `0x${packetDataBuffer.readUInt16BE(transportHeaderStart + 2).toString(16)}` };
                                  info += ` Type ${icmpType} Code ${icmpCode}`;
                              }
                          } else if (ipProtocolField === 6) { // TCP
                              protocol = "TCP";
                              transportProtocolName = "TCP";
                              if (packetDataBuffer.length >= transportHeaderStart + 20) { 
                                  const tcpHeaderBasic = packetDataBuffer.slice(transportHeaderStart, transportHeaderStart + 20);
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
                                  // Perbaiki perhitungan Len: capturedLength dikurangi awal header TCP
                                  const payloadLength = capturedLength - (transportHeaderStart + tcpHeaderLength);
                                  info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq} Ack=${tcpAck} Win=${windowSize} Len=${payloadLength >= 0 ? payloadLength : 0}`;
                                  detailedInfo["TCP"] = { 
                                      SourcePort: sourcePort, DestinationPort: destPort, 
                                      SequenceNumber: tcpSeq, AckNumber: tcpAck, HeaderLength: tcpHeaderLength,
                                      Flags: flags.join(', '), WindowSize: windowSize,
                                      Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`,
                                      UrgentPointer: tcpHeaderBasic.readUInt16BE(18)
                                  };
                                  if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; }
                              } else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; }
                          } else if (ipProtocolField === 17) { // UDP
                              protocol = "UDP";
                              transportProtocolName = "UDP";
                               if (packetDataBuffer.length >= transportHeaderStart + 8) { 
                                  const udpHeader = packetDataBuffer.slice(transportHeaderStart, transportHeaderStart + 8);
                                  sourcePort = udpHeader.readUInt16BE(0);
                                  destPort = udpHeader.readUInt16BE(2);
                                  const udpLength = udpHeader.readUInt16BE(4); // Ini adalah panjang header UDP + data UDP
                                  info = `${sourcePort} → ${destPort} Len=${udpLength - 8}`; // Panjang data UDP
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
              } else if (etherType === 0x86DD) { // IPv6
                 protocol = "IPv6";
                 info = "IPv6 Packet (detail parsing not fully implemented)";
                 detailedInfo["IPv6"] = { Payload: "Further parsing needed for IPv6 details" };
              } else if (etherType === 0x0806) { // ARP
                 protocol = "ARP";
                 info = "ARP Packet (detail parsing not fully implemented)";
                 detailedInfo["ARP"] = { Payload: "Further parsing needed for ARP details" };
              } else {
                 protocol = `UnknownEtherType_0x${etherType.toString(16)}`;
                 info = `Unknown EtherType 0x${etherType.toString(16)}`;
              }
          } else if (linkLayerType !==1) { // Non-Ethernet
            protocol = `LinkType_${linkLayerType}`;
            info = `Packet with Link Layer Type ${linkLayerType} (not Ethernet, raw data shown)`;
            detailedInfo[protocol] = { DataLength: packetDataBuffer.length };
          } else {
            info = "Packet too short for Ethernet header";
            isError = true; errorType = "ShortPacket";
          }

          const maxHexDumpBytes = 64; // Sama
          const dataToDump = packetDataBuffer || Buffer.alloc(0);
          const actualDataToDump = dataToDump.slice(0, Math.min(dataToDump.length, maxHexDumpBytes));
          for (let i = 0; i < actualDataToDump.length; i += 16) {
              const slice = actualDataToDump.slice(i, i + 16);
              const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || '';
              const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
              hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`);
          }
      } catch (e: any) { 
          console.warn(`[API_GET_PACKET_DATA_PCAPNG] Error decoding individual packet ${packetCounter}: ${e.message}`);
          info = `Error decoding: ${e.message}`;
          isError = true;
          errorType = "DecodingError";
      }

      const finalPacketData = {
        id: packetCounter, timestamp,
        sourceIp, sourcePort, destIp, destPort, protocol,
        length: capturedLength, info, flags,
        tcpSeq, tcpAck, windowSize, ttl,
        isError, errorType, hexDump, detailedInfo
      };
      parsedPackets.push(finalPacketData);

      // Logika pembuatan koneksi (tetap sama)
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
        console.warn(`[API_GET_PACKET_DATA_PCAPNG] Reached packet display limit: ${MAX_PACKETS_FOR_UI_DISPLAY}`);
        generateAndResolveConnections(); 
      }
    }); 
    
    const generateAndResolveConnections = () => {
        if (promiseResolved) return; 
        const connections = Array.from(connectionMap.values());
        console.log(`[API_GET_PACKET_DATA_PCAPNG] Resolving with ${parsedPackets.length} packets and ${connections.length} connections.`);
        resolveOnce({ packets: parsedPackets, connections });
    };
    
    parser.on('end', () => {
      if (promiseResolved) return;
      console.log(`[API_GET_PACKET_DATA_PCAPNG] Finished parsing PCAP stream. Total packets: ${packetCounter}`);
      generateAndResolveConnections();
    });

    parser.on('error', (err: Error) => {
      if (promiseResolved) return;
      console.error(`[API_GET_PACKET_DATA_PCAPNG] Error parsing PCAP stream:`, err);
      rejectOnce(new Error(`Error parsing PCAP stream: ${err.message}`));
    });
  }); 
}


export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const analysisIdFromParams = params.id;
    if (!analysisIdFromParams) {
      console.error("[API_GET_PACKET_DATA] Analysis ID missing from params.id"); 
      return NextResponse.json({ error: "Analysis ID is required in path" }, { status: 400 });
    }

    console.log(`[API_GET_PACKET_DATA] Request received for analysisId (from params.id): ${analysisIdFromParams}`);
    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromParams });

    if (!pcapRecord || !pcapRecord.blobUrl) {
      console.error(`[API_GET_PACKET_DATA] PCAP file or blobUrl not found for analysisId: ${analysisIdFromParams}`);
      return NextResponse.json({ error: "PCAP file not found for this analysis" }, { status: 404 });
    }
    
    // Gunakan fungsi parser baru
    const pcapData = await parsePcapFileWithPcapNgParser(pcapRecord.blobUrl, pcapRecord.originalName);

    return NextResponse.json({ success: true, ...pcapData });

  } catch (error) {
    console.error("[API_GET_PACKET_DATA] Error fetching packet data:", error);
    const errorMessage = error instanceof Error ? error.message : "Failed to fetch packet data";
    return NextResponse.json({ success: false, error: errorMessage, details: error instanceof Error ? error.stack : "No stack available" }, { status: 500 });
  }
}
