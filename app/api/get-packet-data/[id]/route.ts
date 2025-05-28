// app/api/get-packet-data/[id]/route.ts
import { type NextRequest, NextResponse } from "next/server";
import db from "@/lib/neon-db";
const PcapParser = require('pcap-parser'); // Parser lama untuk .pcap
const PCAPNGParser = require('pcap-ng-parser'); // Parser baru untuk .pcapng
import { Readable } from 'stream';

// --- Fungsi Helper Timestamp untuk PCAPNGParser ---
function pcapNgTimestampToDate(timestampHigh: number, timestampLow: number): Date {
  const timestampBigInt = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
  const milliseconds = timestampBigInt / 1000n;
  return new Date(Number(milliseconds));
}

// --- Fungsi Parsing menggunakan PcapParser (Parser Lama untuk .pcap) ---
// Ini adalah versi yang disederhanakan dari fungsi parsing asli Anda.
// Anda mungkin perlu menyesuaikannya agar cocok persis dengan implementasi lama Anda
// jika ada logika decoding yang lebih spesifik yang hilang.
async function parsePcapWithOriginalParser(fileUrl: string, fileName: string, analysisId: string): Promise<{ packets: any[], connections: any[] }> {
  console.log(`[ORIGINAL_PARSER] Parsing .pcap: ${fileName} (ID: ${analysisId})`);
  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[ORIGINAL_PARSER] Failed to download .pcap file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = PcapParser.parse(readablePcapStream); // Menggunakan PcapParser

  const parsedPackets: any[] = [];
  let packetCounter = 0;
  const MAX_PACKETS_FOR_UI_DISPLAY = 500;
  let promiseResolved = false;
  const connectionMap = new Map<string, any>();

  return new Promise((resolve, reject) => {
    const resolveOnce = (data: { packets: any[], connections: any[] }) => {
      if (!promiseResolved) {
        promiseResolved = true;
        if (parser && typeof parser.removeAllListeners === 'function') parser.removeAllListeners();
        if (readablePcapStream && !readablePcapStream.destroyed) readablePcapStream.destroy();
        resolve(data);
      }
    };
    const rejectOnce = (error: Error) => {
      if (!promiseResolved) {
        promiseResolved = true;
        if (parser && typeof parser.removeAllListeners === 'function') parser.removeAllListeners();
        if (readablePcapStream && !readablePcapStream.destroyed) readablePcapStream.destroy();
        reject(error);
      }
    };

    parser.on('packet', (packet: any) => { // 'packet' event dari pcap-parser
      if (promiseResolved) return;
      packetCounter++;

      let sourceIp = "N/A"; /* ... (Logika decoding Anda yang sudah ada untuk pcap-parser) ... */
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

      try {
        // Implementasi decoding paket Anda yang sudah ada untuk pcap-parser
        // Contoh sangat dasar:
        if (packet.data && packet.data.length >= 14) {
          const etherType = packet.data.readUInt16BE(12);
          if (etherType === 0x0800) { // IPv4
            protocol = "IPv4";
            if (packet.data.length >= 34) { // Minimal Ethernet + IPv4 header
                 sourceIp = `${packet.data[26]}.${packet.data[27]}.${packet.data[28]}.${packet.data[29]}`;
                 destIp = `${packet.data[30]}.${packet.data[31]}.${packet.data[32]}.${packet.data[33]}`;
                 const ipProtocolField = packet.data[23];
                 if (ipProtocolField === 6) protocol = "TCP";
                 else if (ipProtocolField === 17) protocol = "UDP";
                 else if (ipProtocolField === 1) protocol = "ICMP";
                 info = `IPv4 ${sourceIp} -> ${destIp} (${protocol})`;
                 // Anda perlu melengkapi bagian ini dengan logika decoding yang lebih detail dari kode Anda sebelumnya
            }
          } else if (etherType === 0x86DD) { protocol = "IPv6"; info = "IPv6 Packet"; }
          else if (etherType === 0x0806) { protocol = "ARP"; info = "ARP Packet"; }
          else { protocol = `EtherType_0x${etherType.toString(16)}`; }
        }
      } catch(e: any) {
        info = `Error decoding: ${e.message}`; isError = true; errorType = "DecodingError_PcapParser";
      }
      // ... (Sisa logika untuk mengisi finalPacketData dan connectionMap dari pcap-parser) ...

      const finalPacketData = { id: packetCounter, timestamp: detailedInfo["Frame Info"].Timestamp, sourceIp, sourcePort, destIp, destPort, protocol, length: packet.header.capturedLength, info, flags, tcpSeq, tcpAck, windowSize, ttl, isError, errorType, hexDump, detailedInfo };
      parsedPackets.push(finalPacketData);

      if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") {
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`; const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`; const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd;
          if (!connectionMap.has(connId)) { connectionMap.set(connId, { id: connId, sourceIp, sourcePort, destIp, destPort, protocol, state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp, hasErrors: isError, errorTypes: isError && errorType ? [errorType] : [] });
          } else { const conn = connectionMap.get(connId); conn.packets.push(packetCounter); conn.endTime = finalPacketData.timestamp; if (isError && !conn.hasErrors) conn.hasErrors = true; if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType); if (protocol === "TCP") { if (flags.includes("RST")) conn.state = "RESET"; else if (flags.includes("FIN") && flags.includes("ACK")) conn.state = "FIN_ACK"; else if (flags.includes("FIN") && conn.state !== "RESET") conn.state = "FIN_WAIT"; else if (flags.includes("SYN") && flags.includes("ACK") && conn.state === "SYN_SENT") conn.state = "ESTABLISHED"; else if (flags.includes("SYN") && conn.state !== "ESTABLISHED" && conn.state !== "RESET") conn.state = "SYN_SENT"; } }
      }


      if (packetCounter >= MAX_PACKETS_FOR_UI_DISPLAY) {
        console.warn(`[ORIGINAL_PARSER] Reached packet display limit for ${fileName}.`);
        const connections = Array.from(connectionMap.values());
        resolveOnce({ packets: parsedPackets, connections });
      }
    });

    parser.on('end', () => {
      if (promiseResolved) return;
      console.log(`[ORIGINAL_PARSER] Finished parsing .pcap stream for ${fileName}. Total packets: ${packetCounter}`);
      const connections = Array.from(connectionMap.values());
      resolveOnce({ packets: parsedPackets, connections });
    });

    parser.on('error', (err: Error) => {
      if (promiseResolved) return;
      console.error(`[ORIGINAL_PARSER] Error parsing .pcap stream for ${fileName}:`, err);
      rejectOnce(new Error(`Original PcapParser error: ${err.message}`));
    });
  });
}


// --- Fungsi Parsing menggunakan PCAPNGParser (Parser Baru untuk .pcapng) ---
// Ini adalah fungsi `parsePcapFileWithPcapNgParserDiagnostics` yang sudah kita buat,
// mungkin kita bisa menamainya lebih generik seperti `parsePcapNgWithNewParser`
async function parsePcapNgWithNewParser(fileUrl: string, fileName: string, analysisId: string): Promise<{ packets: any[], connections: any[] }> {
  const functionStartTime = Date.now();
  console.log(`[PCAPNG_PARSER_DIAG] START Parsing ID: ${analysisId}, File: ${fileName}`);
  console.time(`[PCAPNG_PARSER_DIAG_TOTAL_TIME]_ID-${analysisId}`);

  let pcapBuffer: Buffer;
  try {
    console.time(`[PCAPNG_PARSER_DIAG_DOWNLOAD]_ID-${analysisId}`);
    const pcapResponse = await fetch(fileUrl);
    if (!pcapResponse.ok || !pcapResponse.body) {
      console.error(`[PCAPNG_PARSER_DIAG] Failed to download PCAPNG: ${pcapResponse.status} ${pcapResponse.statusText}`);
      throw new Error(`Failed to download PCAPNG file: ${pcapResponse.statusText}`);
    }
    const arrayBuffer = await pcapResponse.arrayBuffer();
    pcapBuffer = Buffer.from(arrayBuffer);
    console.timeEnd(`[PCAPNG_PARSER_DIAG_DOWNLOAD]_ID-${analysisId}`);
    console.log(`[PCAPNG_PARSER_DIAG] Downloaded ${fileName} (${(pcapBuffer.length / (1024*1024)).toFixed(3)} MB)`);
  } catch (downloadError) {
    console.error(`[PCAPNG_PARSER_DIAG] Download error for ${fileName}:`, downloadError);
    throw downloadError;
  }

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = new PCAPNGParser();

  const parsedPackets: any[] = [];
  let packetCounter = 0;
  const MAX_PACKETS_FOR_DIAGNOSTICS = 1000; // Tetap batasi untuk diagnostik timeout
  let promiseResolved = false;

  const connectionMap = new Map<string, any>();
  let currentInterfaceInfo: any = {};
  let blockCounter = 0;

  console.time(`[PCAPNG_PARSER_DIAG_PARSING_INSTANCE]_ID-${analysisId}`);

  return new Promise((resolve, reject) => {
    const cleanupAndResolve = (data: { packets: any[], connections: any[] }) => {
        if (!promiseResolved) {
          promiseResolved = true;
          console.log(`[PCAPNG_PARSER_DIAG] Cleanup & Resolve for ${analysisId}. Packets: ${packetCounter}, Blocks: ${blockCounter}`);
          console.timeEnd(`[PCAPNG_PARSER_DIAG_PARSING_INSTANCE]_ID-${analysisId}`);
          console.timeEnd(`[PCAPNG_PARSER_DIAG_TOTAL_TIME]_ID-${analysisId}`);
          if (parser) parser.removeAllListeners();
          if (readablePcapStream && !readablePcapStream.destroyed) { readablePcapStream.unpipe(parser); readablePcapStream.destroy(); }
          resolve(data);
        }
    };
    const cleanupAndReject = (error: Error) => {
        if (!promiseResolved) {
          promiseResolved = true;
          console.error(`[PCAPNG_PARSER_DIAG] Cleanup & Reject for ${analysisId}. Error: ${error.message}. Packets: ${packetCounter}, Blocks: ${blockCounter}`);
          console.timeEnd(`[PCAPNG_PARSER_DIAG_PARSING_INSTANCE]_ID-${analysisId}`);
          console.timeEnd(`[PCAPNG_PARSER_DIAG_TOTAL_TIME]_ID-${analysisId}`);
          if (parser) parser.removeAllListeners();
          if (readablePcapStream && !readablePcapStream.destroyed) { readablePcapStream.unpipe(parser); readablePcapStream.destroy(); }
          reject(error);
        }
    };

    readablePcapStream.pipe(parser);

    parser.on('block', (block: any) => {
        blockCounter++;
        if (block.type === 'InterfaceDescriptionBlock') {
            currentInterfaceInfo[block.interfaceId] = { name: block.options?.if_name, linkLayerType: block.linkLayerType, snapLength: block.snapLength };
        }
    });

    parser.on('data', (parsedPcapNgPacket: any) => {
      if (promiseResolved) return;
      if (parsedPcapNgPacket.type !== 'EnhancedPacketBlock' && parsedPcapNgPacket.type !== 'PacketBlock') return;
      if (!parsedPcapNgPacket.data) return;
      
      console.time(`[PCAPNG_PARSER_DIAG_PACKET_PROC]_ID-${analysisId}_PKT-${packetCounter + 1}`);
      packetCounter++;
      
      const packetDataBuffer = parsedPcapNgPacket.data;
      let timestampDate;
      if (parsedPcapNgPacket.timestampHigh !== undefined && parsedPcapNgPacket.timestampLow !== undefined) timestampDate = pcapNgTimestampToDate(parsedPcapNgPacket.timestampHigh, parsedPcapNgPacket.timestampLow);
      else if (parsedPcapNgPacket.timestampSeconds !== undefined) timestampDate = new Date(parsedPcapNgPacket.timestampSeconds * 1000 + (parsedPcapNgPacket.timestampMicroseconds || 0) / 1000);
      else timestampDate = new Date();
      const timestamp = timestampDate.toISOString();

      const capturedLength = parsedPcapNgPacket.capturedLength || packetDataBuffer.length;
      const originalLength = parsedPcapNgPacket.originalPacketLength || packetDataBuffer.length;
      const interfaceId = parsedPcapNgPacket.interfaceId || 0;
      const ifaceInfo = currentInterfaceInfo[interfaceId] || { name: `Interface ${interfaceId}`, linkLayerType: 1, snapLength: 65535 };

      let sourceIp = "N/A"; /* ... (Logika decoding Anda yang sudah ada untuk pcap-ng-parser) ... */
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
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, CapturedLength: capturedLength, OriginalLength: originalLength, Timestamp: timestamp, InterfaceID: interfaceId, InterfaceName: ifaceInfo.name, LinkLayerType: ifaceInfo.linkLayerType }};
      let hexDump : string[] = [];
      const linkLayerType = ifaceInfo.linkLayerType;

      try { /* ... (Salin logika decoding paket dari versi pcap-ng-parser sebelumnya) ... */
          if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >= 14) { 
              detailedInfo["Ethernet II"] = { DestinationMAC: packetDataBuffer.slice(0,6).toString('hex').match(/.{1,2}/g)?.join(':'), SourceMAC: packetDataBuffer.slice(6,12).toString('hex').match(/.{1,2}/g)?.join(':'), EtherType: `0x${packetDataBuffer.readUInt16BE(12).toString(16)}` }; 
              const etherType = packetDataBuffer.readUInt16BE(12);
              if (etherType === 0x0800) { // IPv4
                  protocol = "IPv4"; 
                  if (packetDataBuffer.length >= 14 + 20) { 
                      const ipHeaderStart = 14; const ipHeaderIHL = (packetDataBuffer[ipHeaderStart] & 0x0F); const ipHeaderLength = ipHeaderIHL * 4;
                      if (packetDataBuffer.length >= ipHeaderStart + ipHeaderLength) {
                          const ipHeader = packetDataBuffer.slice(ipHeaderStart, ipHeaderStart + ipHeaderLength); sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`; destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`; ttl = ipHeader[8]; const ipProtocolField = ipHeader[9]; detailedInfo["IPv4"] = { Version: 4, HeaderLength: ipHeaderLength, TTL: ttl, Protocol: ipProtocolField, SourceAddress: sourceIp, DestinationAddress: destIp, TotalLength: ipHeader.readUInt16BE(2), Identification: `0x${ipHeader.readUInt16BE(4).toString(16)}` }; info = `IPv4 ${sourceIp} -> ${destIp}`; const transportHeaderStart = ipHeaderStart + ipHeaderLength; let transportProtocolName = `IPProto_${ipProtocolField}`;
                          if (ipProtocolField === 1) { protocol = "ICMP"; transportProtocolName = "ICMP"; info += ` (ICMP)`; if (packetDataBuffer.length >= transportHeaderStart + 4) { const icmpType = packetDataBuffer[transportHeaderStart]; const icmpCode = packetDataBuffer[transportHeaderStart + 1]; detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode, Checksum: `0x${packetDataBuffer.readUInt16BE(transportHeaderStart + 2).toString(16)}` }; info += ` Type ${icmpType} Code ${icmpCode}`; }}
                          else if (ipProtocolField === 6) { protocol = "TCP"; transportProtocolName = "TCP"; if (packetDataBuffer.length >= transportHeaderStart + 20) { const tcpHeaderBasic = packetDataBuffer.slice(transportHeaderStart, transportHeaderStart + 20); sourcePort = tcpHeaderBasic.readUInt16BE(0); destPort = tcpHeaderBasic.readUInt16BE(2); tcpSeq = tcpHeaderBasic.readUInt32BE(4); tcpAck = tcpHeaderBasic.readUInt32BE(8); const dataOffsetByte = tcpHeaderBasic[12]; const tcpHeaderLength = ((dataOffsetByte & 0xF0) >> 4) * 4; const flagsByte = tcpHeaderBasic[13]; flags = []; if (flagsByte & 0x01) flags.push("FIN"); if (flagsByte & 0x02) flags.push("SYN"); if (flagsByte & 0x04) flags.push("RST"); if (flagsByte & 0x08) flags.push("PSH"); if (flagsByte & 0x10) flags.push("ACK"); if (flagsByte & 0x20) flags.push("URG"); windowSize = tcpHeaderBasic.readUInt16BE(14); const payloadLength = capturedLength - (transportHeaderStart + tcpHeaderLength); info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq} Ack=${tcpAck} Win=${windowSize} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["TCP"] = { SourcePort: sourcePort, DestinationPort: destPort, SequenceNumber: tcpSeq, AckNumber: tcpAck, HeaderLength: tcpHeaderLength, Flags: flags.join(', '), WindowSize: windowSize, Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`, UrgentPointer: tcpHeaderBasic.readUInt16BE(18) }; if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; }} else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; }}
                          else if (ipProtocolField === 17) { protocol = "UDP"; transportProtocolName = "UDP"; if (packetDataBuffer.length >= transportHeaderStart + 8) { const udpHeader = packetDataBuffer.slice(transportHeaderStart, transportHeaderStart + 8); sourcePort = udpHeader.readUInt16BE(0); destPort = udpHeader.readUInt16BE(2); const udpLength = udpHeader.readUInt16BE(4); info = `${sourcePort} → ${destPort} Len=${udpLength - 8}`; detailedInfo["UDP"] = { SourcePort: sourcePort, DestinationPort: destPort, Length: udpLength, Checksum: `0x${udpHeader.readUInt16BE(6).toString(16)}` }; } else { info = "UDP (Truncated Header)"; isError = true; errorType = "TruncatedUDP"; }}
                          else { protocol = transportProtocolName; info = `IP Protocol ${ipProtocolField}`; }
                      } else { info = "IPv4 (Truncated IP Header)"; isError = true; errorType = "TruncatedIP"; protocol = "IPv4"; }
                  } else { info = "IPv4 (Short Packet)"; isError = true; errorType = "ShortIPPacket"; protocol = "IPv4"; }
              } else if (etherType === 0x86DD) { protocol = "IPv6"; info = "IPv6 Packet"; detailedInfo["IPv6"] = { Payload: "IPv6 detail parsing TBD" }; }
              else if (etherType === 0x0806) { protocol = "ARP"; info = "ARP Packet"; detailedInfo["ARP"] = { Payload: "ARP detail parsing TBD" }; }
              else { protocol = `UnknownEtherType_0x${etherType.toString(16)}`; info = `Unknown EtherType 0x${etherType.toString(16)}`; }
          } else if (linkLayerType !==1) { protocol = `LinkType_${linkLayerType}`; info = `Packet with Link Layer Type ${linkLayerType}`; detailedInfo[protocol] = { DataLength: packetDataBuffer.length }; }
          else { info = "Packet too short for Ethernet"; isError = true; errorType = "ShortPacket"; }
          const maxHexDumpBytes = 64; const dataToDump = packetDataBuffer || Buffer.alloc(0); const actualDataToDump = dataToDump.slice(0, Math.min(dataToDump.length, maxHexDumpBytes)); for (let i = 0; i < actualDataToDump.length; i += 16) { const slice = actualDataToDump.slice(i, i + 16); const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || ''; const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.'); hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`); }
      } catch (e: any) { info = `Error decoding: ${e.message}`; isError = true; errorType = "DecodingError_PcapNgParser"; }
      // ... (akhir logika decoding paket) ...
      
      const finalPacketData = { id: packetCounter, timestamp, sourceIp, sourcePort, destIp, destPort, protocol, length: capturedLength, info, flags, tcpSeq, tcpAck, windowSize, ttl, isError, errorType, hexDump, detailedInfo };
      parsedPackets.push(finalPacketData);

      if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") { /* ... logika koneksi ... */
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`; const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`; const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd;
          if (!connectionMap.has(connId)) { connectionMap.set(connId, { id: connId, sourceIp, sourcePort, destIp, destPort, protocol, state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp, hasErrors: isError, errorTypes: isError && errorType ? [errorType] : [] });
          } else { const conn = connectionMap.get(connId); conn.packets.push(packetCounter); conn.endTime = finalPacketData.timestamp; if (isError && !conn.hasErrors) conn.hasErrors = true; if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType); if (protocol === "TCP") { if (flags.includes("RST")) conn.state = "RESET"; else if (flags.includes("FIN") && flags.includes("ACK")) conn.state = "FIN_ACK"; else if (flags.includes("FIN") && conn.state !== "RESET") conn.state = "FIN_WAIT"; else if (flags.includes("SYN") && flags.includes("ACK") && conn.state === "SYN_SENT") conn.state = "ESTABLISHED"; else if (flags.includes("SYN") && conn.state !== "ESTABLISHED" && conn.state !== "RESET") conn.state = "SYN_SENT"; } }
      }
      
      console.timeEnd(`[PCAPNG_PARSER_DIAG_PACKET_PROC]_ID-${analysisId}_PKT-${packetCounter}`);
      if (packetCounter % 10 === 0) console.log(`[PCAPNG_PARSER_DIAG] Processed packet ${packetCounter} for ${analysisId}.`);

      if (packetCounter >= MAX_PACKETS_FOR_DIAGNOSTICS) {
        console.warn(`[PCAPNG_PARSER_DIAG] Reached DIAGNOSTICS packet limit for ${analysisId}.`);
        generateAndResolveConnections(); 
      }
    }); 
    
    const generateAndResolveConnections = () => {
        if (promiseResolved) return; 
        const connections = Array.from(connectionMap.values());
        cleanupAndResolve({ packets: parsedPackets, connections });
    };
    
    parser.on('end', () => {
      if (promiseResolved) return;
      console.log(`[PCAPNG_PARSER_DIAG] Stream ended for ${analysisId}. Blocks: ${blockCounter}, Packets: ${packetCounter}.`);
      generateAndResolveConnections();
    });
    parser.on('error', (err: Error) => { if (promiseResolved) return; cleanupAndReject(new Error(`PCAPNGParser stream error: ${err.message}`)); });
    readablePcapStream.on('error', (err: Error) => { if (promiseResolved) return; cleanupAndReject(new Error(`ReadablePcapStream error: ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { generateAndResolveConnections(); }});
  }); 
}

// --- Fungsi GET Utama dengan Logika Pemilihan Parser ---
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const VERCEL_TIMEOUT_SAFETY_MARGIN = 4000; 
  const functionTimeout = (process.env.VERCEL_FUNCTION_MAX_DURATION ? parseInt(process.env.VERCEL_FUNCTION_MAX_DURATION) * 1000 : 10000) - VERCEL_TIMEOUT_SAFETY_MARGIN; 
  const overallStartTime = Date.now();
  let timeoutId: NodeJS.Timeout | null = null;
  const analysisIdFromParams = params.id;

  try {
    if (!analysisIdFromParams) {
      return NextResponse.json({ error: "Analysis ID is required in path" }, { status: 400 });
    }
    console.log(`[API_GET_PACKET_DATA_ROUTER] Request for analysisId: ${analysisIdFromParams}. Timeout ~${functionTimeout / 1000}s.`);
    
    const pcapRecordPromise = db.pcapFile.findUnique({ analysisId: analysisIdFromParams });
    const timeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error(`DB query or initial setup timeout (> ${functionTimeout}ms)`)), functionTimeout);
    });

    const pcapRecord = await Promise.race([pcapRecordPromise, timeoutPromise]) as any;
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = null; // Reset timeoutId

    if (!pcapRecord || pcapRecord instanceof Error) {
        if (pcapRecord instanceof Error) throw pcapRecord;
        return NextResponse.json({ error: "PCAP file metadata not found (or initial timeout)." }, { status: 404 });
    }
    if (!pcapRecord.blobUrl) {
        return NextResponse.json({ error: "PCAP file URL not found." }, { status: 404 });
    }

    let pcapDataPromise;
    const fileName = pcapRecord.originalName || pcapRecord.fileName || "unknown_file";

    // Logika pemilihan parser berdasarkan ekstensi file
    if (fileName.toLowerCase().endsWith(".pcapng")) {
      console.log(`[API_GET_PACKET_DATA_ROUTER] Using PCAPNG_PARSER for ${fileName}`);
      pcapDataPromise = parsePcapNgWithNewParser(pcapRecord.blobUrl, fileName, analysisIdFromParams);
    } else if (fileName.toLowerCase().endsWith(".pcap")) {
      console.log(`[API_GET_PACKET_DATA_ROUTER] Using ORIGINAL_PARSER (pcap-parser) for ${fileName}`);
      pcapDataPromise = parsePcapWithOriginalParser(pcapRecord.blobUrl, fileName, analysisIdFromParams);
    } else {
      console.warn(`[API_GET_PACKET_DATA_ROUTER] Unknown file extension for ${fileName}. Defaulting to PCAPNG_PARSER.`);
      // Default ke pcap-ng-parser jika ekstensi tidak dikenal atau tidak ada
      pcapDataPromise = parsePcapNgWithNewParser(pcapRecord.blobUrl, fileName, analysisIdFromParams);
    }
    
    // Timeout untuk tahap parsing
    const parsingTimeoutPromise = new Promise((_, reject) => {
      const remainingTime = Math.max(1000, functionTimeout - (Date.now() - overallStartTime));
      timeoutId = setTimeout(() => {
        console.warn(`[API_GET_PACKET_DATA_ROUTER] Parsing specific timeout for ${analysisIdFromParams}.`);
        reject(new Error(`Parsing aborted: Timeout during PCAP processing (>${remainingTime}ms remaining).`));
      }, remainingTime);
    });

    const result = await Promise.race([pcapDataPromise, parsingTimeoutPromise]) as { packets: any[], connections: any[] };
    if (timeoutId) clearTimeout(timeoutId);
    
    console.log(`[API_GET_PACKET_DATA_ROUTER] Success for ${analysisIdFromParams}. Total GET time: ${((Date.now() - overallStartTime) / 1000).toFixed(2)}s`);
    return NextResponse.json({ success: true, ...result });

  } catch (error) {
    if (timeoutId) clearTimeout(timeoutId);
    const totalErrorTime = Date.now() - overallStartTime;
    console.error(`[API_GET_PACKET_DATA_ROUTER] Error in GET for ${analysisIdFromParams}. Total time: ${(totalErrorTime / 1000).toFixed(2)}s. Error:`, error);
    const errorMessage = error instanceof Error ? error.message : "Failed to fetch packet data";
    const isTimeoutError = errorMessage.includes("timeout") || errorMessage.includes("aborted");
    return NextResponse.json({ 
        success: false, 
        error: isTimeoutError ? "Operation timed out. The PCAP file may be too complex for current limits." : errorMessage,
        details: error instanceof Error ? error.stack : "No stack",
        errorCode: isTimeoutError ? "TIMEOUT_ERROR" : "PARSING_ERROR"
    }, { status: 500 });
  }
}
