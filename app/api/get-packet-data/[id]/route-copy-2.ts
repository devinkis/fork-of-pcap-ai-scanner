// app/api/get-packet-data/[id]/route.ts
import { type NextRequest, NextResponse } from "next/server";
import db from "@/lib/neon-db";
const PCAPNGParser = require('pcap-ng-parser');
import { Readable } from 'stream';

// Fungsi helper untuk konversi timestamp pcap-ng
function pcapNgTimestampToDate(timestampHigh: number, timestampLow: number): Date {
  const seconds = timestampHigh * (2**32 / 1e6) + timestampLow / 1e6; // Mengasumsikan unit adalah microsecond
  return new Date(seconds * 1000); // Konversi ke milisecond untuk Date
}

async function parsePcapFileWithPcapNgParser(fileUrl: string, fileName: string): Promise<{ packets: any[], connections: any[] }> {
  const startTime = Date.now();
  console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] START Parsing: ${fileName} from ${fileUrl} at ${new Date(startTime).toISOString()}`);
  
  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    console.error(`[API_GET_PACKET_DATA_V2_PCAPNG] Failed to download PCAP: ${pcapResponse.status} ${pcapResponse.statusText}`);
    throw new Error(`Failed to download PCAP file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);
  const downloadTime = Date.now();
  console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] Downloaded ${fileName} (${(pcapBuffer.length / (1024*1024)).toFixed(2)} MB) in ${((downloadTime - startTime) / 1000).toFixed(2)}s`);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = new PCAPNGParser();

  const parsedPackets: any[] = [];
  let packetCounter = 0;
  // **MITIGASI 1: Kurangi jumlah paket untuk UI secara drastis**
  const MAX_PACKETS_FOR_UI_DISPLAY = 100; // Coba dengan 100 dulu, atau bahkan 50
  let promiseResolved = false;

  const connectionMap = new Map<string, any>();
  let currentInterfaceInfo: any = null;
  let firstPacketTime: number | null = null;
  let lastPacketTime: number | null = null;

  return new Promise((resolve, reject) => {
    const cleanupAndResolve = (data: { packets: any[], connections: any[] }) => {
        if (!promiseResolved) {
          promiseResolved = true;
          console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] Cleanup: Removing listeners and destroying stream for ${fileName}`);
          if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
          if (readablePcapStream && !readablePcapStream.destroyed) {
            readablePcapStream.unpipe(parser); // Penting untuk diunpipe sebelum destroy
            readablePcapStream.destroy();
          }
          resolve(data);
        }
    };
    const cleanupAndReject = (error: Error) => {
        if (!promiseResolved) {
          promiseResolved = true;
          console.error(`[API_GET_PACKET_DATA_V2_PCAPNG] Cleanup due to error for ${fileName}: ${error.message}`);
          if (parser && typeof parser.removeAllListeners === 'function') {
            parser.removeAllListeners();
          }
           if (readablePcapStream && !readablePcapStream.destroyed) {
            readablePcapStream.unpipe(parser);
            readablePcapStream.destroy();
          }
          reject(error);
        }
    };

    readablePcapStream.pipe(parser);

    parser.on('interface', (interfaceDescription: any) => {
      // console.log('[API_GET_PACKET_DATA_V2_PCAPNG] Interface Description Block:', interfaceDescription);
      currentInterfaceInfo = interfaceDescription;
    });
    
    parser.on('data', (parsedPcapNgPacket: any) => {
      if (promiseResolved) return;

      const packetProcessStartTime = Date.now();
      if (!firstPacketTime) firstPacketTime = packetProcessStartTime;

      if (parsedPcapNgPacket.type !== 'EnhancedPacketBlock' || !parsedPcapNgPacket.data) {
        return;
      }

      packetCounter++;
      
      const packetDataBuffer = parsedPcapNgPacket.data;
      const packetDate = pcapNgTimestampToDate(parsedPcapNgPacket.timestampHigh, parsedPcapNgPacket.timestampLow);
      const timestamp = packetDate.toISOString();
      const capturedLength = parsedPcapNgPacket.capturedLength || packetDataBuffer.length;
      const originalLength = parsedPcapNgPacket.originalPacketLength || packetDataBuffer.length;

      // ... (sisa logika decoding paket tetap sama seperti sebelumnya) ...
      // Ini bagian yang intensif CPU
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
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, CapturedLength: capturedLength, OriginalLength: originalLength, Timestamp: timestamp, InterfaceID: parsedPcapNgPacket.interfaceId }};
      if (currentInterfaceInfo && currentInterfaceInfo.id === parsedPcapNgPacket.interfaceId) {
        detailedInfo["Frame Info"].InterfaceName = currentInterfaceInfo.name || `Interface ${currentInterfaceInfo.id}`;
        detailedInfo["Frame Info"].LinkLayerType = currentInterfaceInfo.linkLayerType;
      }
      let hexDump : string[] = [];
      const linkLayerType = (currentInterfaceInfo && currentInterfaceInfo.id === parsedPcapNgPacket.interfaceId) ? currentInterfaceInfo.linkLayerType : 1;

      try { 
          if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >= 14) { 
              detailedInfo["Ethernet II"] = { 
                DestinationMAC: packetDataBuffer.slice(0,6).toString('hex').match(/.{1,2}/g)?.join(':'),
                SourceMAC: packetDataBuffer.slice(6,12).toString('hex').match(/.{1,2}/g)?.join(':'),
                EtherType: `0x${packetDataBuffer.readUInt16BE(12).toString(16)}`
              }; 
              const etherType = packetDataBuffer.readUInt16BE(12);
              if (etherType === 0x0800) { 
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
                          detailedInfo["IPv4"] = { Version: 4, HeaderLength: ipHeaderLength, TTL: ttl, Protocol: ipProtocolField, SourceAddress: sourceIp, DestinationAddress: destIp, TotalLength: ipHeader.readUInt16BE(2), Identification: `0x${ipHeader.readUInt16BE(4).toString(16)}` };
                          info = `IPv4 ${sourceIp} -> ${destIp}`;
                          const transportHeaderStart = ipHeaderStart + ipHeaderLength;
                          let transportProtocolName = `IPProto_${ipProtocolField}`;
                          if (ipProtocolField === 1) { 
                              protocol = "ICMP"; transportProtocolName = "ICMP"; info += ` (ICMP)`;
                              if (packetDataBuffer.length >= transportHeaderStart + 4) {
                                  const icmpType = packetDataBuffer[transportHeaderStart]; const icmpCode = packetDataBuffer[transportHeaderStart + 1];
                                  detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode, Checksum: `0x${packetDataBuffer.readUInt16BE(transportHeaderStart + 2).toString(16)}` };
                                  info += ` Type ${icmpType} Code ${icmpCode}`;
                              }
                          } else if (ipProtocolField === 6) { 
                              protocol = "TCP"; transportProtocolName = "TCP";
                              if (packetDataBuffer.length >= transportHeaderStart + 20) { 
                                  const tcpHeaderBasic = packetDataBuffer.slice(transportHeaderStart, transportHeaderStart + 20);
                                  sourcePort = tcpHeaderBasic.readUInt16BE(0); destPort = tcpHeaderBasic.readUInt16BE(2);
                                  tcpSeq = tcpHeaderBasic.readUInt32BE(4); tcpAck = tcpHeaderBasic.readUInt32BE(8);
                                  const dataOffsetByte = tcpHeaderBasic[12]; const tcpHeaderLength = ((dataOffsetByte & 0xF0) >> 4) * 4;
                                  const flagsByte = tcpHeaderBasic[13];
                                  flags = [];
                                  if (flagsByte & 0x01) flags.push("FIN"); if (flagsByte & 0x02) flags.push("SYN"); if (flagsByte & 0x04) flags.push("RST");
                                  if (flagsByte & 0x08) flags.push("PSH"); if (flagsByte & 0x10) flags.push("ACK"); if (flagsByte & 0x20) flags.push("URG");
                                  windowSize = tcpHeaderBasic.readUInt16BE(14);
                                  const payloadLength = capturedLength - (transportHeaderStart + tcpHeaderLength);
                                  info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq} Ack=${tcpAck} Win=${windowSize} Len=${payloadLength >= 0 ? payloadLength : 0}`;
                                  detailedInfo["TCP"] = { SourcePort: sourcePort, DestinationPort: destPort, SequenceNumber: tcpSeq, AckNumber: tcpAck, HeaderLength: tcpHeaderLength, Flags: flags.join(', '), WindowSize: windowSize, Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`, UrgentPointer: tcpHeaderBasic.readUInt16BE(18) };
                                  if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; }
                              } else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; }
                          } else if (ipProtocolField === 17) { 
                              protocol = "UDP"; transportProtocolName = "UDP";
                               if (packetDataBuffer.length >= transportHeaderStart + 8) { 
                                  const udpHeader = packetDataBuffer.slice(transportHeaderStart, transportHeaderStart + 8);
                                  sourcePort = udpHeader.readUInt16BE(0); destPort = udpHeader.readUInt16BE(2);
                                  const udpLength = udpHeader.readUInt16BE(4);
                                  info = `${sourcePort} → ${destPort} Len=${udpLength - 8}`;
                                  detailedInfo["UDP"] = { SourcePort: sourcePort, DestinationPort: destPort, Length: udpLength, Checksum: `0x${udpHeader.readUInt16BE(6).toString(16)}` };
                               } else { info = "UDP (Truncated Header)"; isError = true; errorType = "TruncatedUDP"; }
                          } else { protocol = transportProtocolName; info = `IP Protocol ${ipProtocolField}`; }
                      } else { info = "IPv4 (Truncated IP Header)"; isError = true; errorType = "TruncatedIP"; protocol = "IPv4"; }
                  } else { info = "IPv4 (Short Packet)"; isError = true; errorType = "ShortIPPacket"; protocol = "IPv4"; }
              } else if (etherType === 0x86DD) { protocol = "IPv6"; info = "IPv6 Packet"; detailedInfo["IPv6"] = { Payload: "IPv6 detail parsing TBD" }; }
              else if (etherType === 0x0806) { protocol = "ARP"; info = "ARP Packet"; detailedInfo["ARP"] = { Payload: "ARP detail parsing TBD" }; }
              else { protocol = `UnknownEtherType_0x${etherType.toString(16)}`; info = `Unknown EtherType 0x${etherType.toString(16)}`; }
          } else if (linkLayerType !==1) {
            protocol = `LinkType_${linkLayerType}`; info = `Packet with Link Layer Type ${linkLayerType}`;
            detailedInfo[protocol] = { DataLength: packetDataBuffer.length };
          } else { info = "Packet too short for Ethernet"; isError = true; errorType = "ShortPacket"; }

          const maxHexDumpBytes = 64;
          const dataToDump = packetDataBuffer || Buffer.alloc(0);
          const actualDataToDump = dataToDump.slice(0, Math.min(dataToDump.length, maxHexDumpBytes));
          for (let i = 0; i < actualDataToDump.length; i += 16) {
              const slice = actualDataToDump.slice(i, i + 16);
              const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || '';
              const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
              hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`);
          }
      } catch (e: any) { 
          console.warn(`[API_GET_PACKET_DATA_V2_PCAPNG] Error decoding packet ${packetCounter}: ${e.message}`);
          info = `Error decoding: ${e.message}`; isError = true; errorType = "DecodingError";
      }
      // ... (akhir logika decoding paket) ...
      
      const finalPacketData = {
        id: packetCounter, timestamp,
        sourceIp, sourcePort, destIp, destPort, protocol,
        length: capturedLength, info, flags,
        tcpSeq, tcpAck, windowSize, ttl,
        isError, errorType, hexDump, detailedInfo
      };
      parsedPackets.push(finalPacketData);

      // Logika pembuatan koneksi tetap sama
      if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") {
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`;
          const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`;
          const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd;
          if (!connectionMap.has(connId)) {
              connectionMap.set(connId, { id: connId, sourceIp, sourcePort, destIp, destPort, protocol, state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp, hasErrors: isError, errorTypes: isError && errorType ? [errorType] : [] });
          } else {
              const conn = connectionMap.get(connId);
              conn.packets.push(packetCounter); conn.endTime = finalPacketData.timestamp;
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
      
      lastPacketTime = Date.now();
      if (packetCounter % 50 === 0) { // Log setiap 50 paket
          console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] Processed packet ${packetCounter} for ${fileName}. Time since first packet: ${((lastPacketTime - (firstPacketTime || packetProcessStartTime)) / 1000).toFixed(2)}s`);
      }

      if (packetCounter >= MAX_PACKETS_FOR_UI_DISPLAY) {
        console.warn(`[API_GET_PACKET_DATA_V2_PCAPNG] Reached packet display limit (${MAX_PACKETS_FOR_UI_DISPLAY}) for ${fileName}. Processing took ${((Date.now() - startTime) / 1000).toFixed(2)}s so far.`);
        generateAndResolveConnections(); 
      }
    }); 
    
    const generateAndResolveConnections = () => {
        if (promiseResolved) return; 
        const connections = Array.from(connectionMap.values());
        const totalProcessingTime = Date.now() - startTime;
        console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] Resolving for ${fileName} with ${parsedPackets.length} packets, ${connections.length} connections. Total time: ${(totalProcessingTime / 1000).toFixed(2)}s`);
        cleanupAndResolve({ packets: parsedPackets, connections });
    };
    
    parser.on('end', () => {
      if (promiseResolved) return;
      const totalProcessingTime = Date.now() - startTime;
      console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] Finished parsing stream for ${fileName}. Total packets: ${packetCounter}. Total time: ${(totalProcessingTime / 1000).toFixed(2)}s`);
      generateAndResolveConnections();
    });

    parser.on('error', (err: Error) => {
      if (promiseResolved) return;
      console.error(`[API_GET_PACKET_DATA_V2_PCAPNG] Error parsing stream for ${fileName}:`, err);
      cleanupAndReject(new Error(`Error parsing PCAP stream: ${err.message}`));
    });
  }); 
}

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const VERCEL_TIMEOUT_SAFETY_MARGIN = 5000; // 5 detik margin keamanan
  const functionTimeout = (process.env.VERCEL_ENV === 'production' ? 10000 : 60000) - VERCEL_TIMEOUT_SAFETY_MARGIN; // 10s Hobby, 60s Pro
  
  const overallStartTime = Date.now();
  let timeoutHit = false;

  const timeoutPromise = new Promise((_, reject) => 
    setTimeout(() => {
      timeoutHit = true;
      console.warn(`[API_GET_PACKET_DATA_V2_PCAPNG] Vercel function timeout approached for analysisId: ${params.id}. Aborting parsing.`);
      reject(new Error(`Parsing aborted due to Vercel function timeout limit (approaching ${functionTimeout / 1000}s). Partial data might be available if parsing started.`));
    }, functionTimeout)
  );

  try {
    const analysisIdFromParams = params.id;
    if (!analysisIdFromParams) {
      return NextResponse.json({ error: "Analysis ID is required in path" }, { status: 400 });
    }

    console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] GET request for analysisId: ${analysisIdFromParams}`);
    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromParams });

    if (!pcapRecord || !pcapRecord.blobUrl) {
      return NextResponse.json({ error: "PCAP file not found for this analysis" }, { status: 404 });
    }
    
    const pcapDataPromise = parsePcapFileWithPcapNgParser(pcapRecord.blobUrl, pcapRecord.originalName);
    
    // Race parsing promise against timeout promise
    const result = await Promise.race([pcapDataPromise, timeoutPromise]) as { packets: any[], connections: any[] };

    if (timeoutHit) { // Jika timeout yang menang race
        // Error sudah di-reject oleh timeoutPromise, blok catch di bawah akan menangani
        // Namun, untuk kejelasan, kita bisa throw error lagi di sini jika perlu.
        // Biasanya, blok catch di bawah akan menangkap error dari timeoutPromise.
        console.error("[API_GET_PACKET_DATA_V2_PCAPNG] Parsing definitively hit timeout. Error should have been thrown.");
        // Fallback jika reject dari timeoutPromise tidak langsung menghentikan eksekusi di sini.
        throw new Error("Parsing aborted due to Vercel function timeout limit.");
    }
    
    console.log(`[API_GET_PACKET_DATA_V2_PCAPNG] Successfully parsed and returning data for ${analysisIdFromParams}. Total GET request time: ${((Date.now() - overallStartTime) / 1000).toFixed(2)}s`);
    return NextResponse.json({ success: true, ...result });

  } catch (error) {
    const totalErrorTime = Date.now() - overallStartTime;
    console.error(`[API_GET_PACKET_DATA_V2_PCAPNG] Error in GET for analysisId ${params.id}. Total time: ${(totalErrorTime / 1000).toFixed(2)}s. Error:`, error);
    const errorMessage = error instanceof Error ? error.message : "Failed to fetch packet data";
    return NextResponse.json({ success: false, error: errorMessage, details: error instanceof Error ? error.stack : "No stack" }, { status: 500 });
  }
}
