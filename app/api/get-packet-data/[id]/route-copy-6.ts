// app/api/get-packet-data/[id]/route.ts
import { type NextRequest, NextResponse } from "next/server";
import db from "@/lib/neon-db";
const PcapParser = require('pcap-parser');
const PCAPNGParser = require('pcap-ng-parser');
import { Readable } from 'stream';

// --- Fungsi Helper Timestamp untuk PCAPNGParser ---
function pcapNgTimestampToDate(timestampHigh: number, timestampLow: number): Date {
  const timestampBigInt = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
  const milliseconds = timestampBigInt / 1000n;
  return new Date(Number(milliseconds));
}

// --- Fungsi Parsing menggunakan PcapParser (Parser Lama untuk .pcap) ---
// ... (Kode parsePcapWithOriginalParser dari respons sebelumnya tetap sama)
async function parsePcapWithOriginalParser(fileUrl: string, fileName: string, analysisId: string): Promise<{ packets: any[], connections: any[] }> {
  console.log(`[REVISIT_PCAP_PARSER] Parsing .pcap: ${fileName} (ID: ${analysisId})`);
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[REVISIT_PCAP_PARSER] Failed to download .pcap file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);
  console.log(`[REVISIT_PCAP_PARSER] Downloaded ${fileName} in ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = PcapParser.parse(readablePcapStream);

  const parsedPackets: any[] = [];
  let packetCounter = 0;
  const MAX_PACKETS_FOR_UI_DISPLAY = 500;
  let promiseResolved = false;
  const connectionMap = new Map<string, any>();

  return new Promise((resolve, reject) => {
    const cleanupAndResolve = (data: { packets: any[], connections: any[] }) => {
      if (!promiseResolved) {
        promiseResolved = true;
        console.log(`[REVISIT_PCAP_PARSER] Resolving for ${analysisId}. Packets: ${packetCounter}. Total time: ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`);
        if (parser) parser.removeAllListeners();
        if (readablePcapStream && !readablePcapStream.destroyed) {
          readablePcapStream.unpipe(parser); 
          readablePcapStream.destroy();
        }
        resolve(data);
      }
    };
    const cleanupAndReject = (error: Error) => {
      if (!promiseResolved) {
        promiseResolved = true;
        console.error(`[REVISIT_PCAP_PARSER] Rejecting for ${analysisId}. Error: ${error.message}`);
        if (parser) parser.removeAllListeners();
        if (readablePcapStream && !readablePcapStream.destroyed) {
          readablePcapStream.unpipe(parser);
          readablePcapStream.destroy();
        }
        reject(error);
      }
    };

    parser.on('packet', (packet: any) => {
      if (promiseResolved) return;
      packetCounter++;
      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = "Raw Data";
      let sourcePort, destPort, tcpSeq, tcpAck, windowSize, ttl;
      let flags: string[] = []; let isError = false; let errorType;
      const packetTimestamp = new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000);
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, CapturedLength: packet.header.capturedLength, OriginalLength: packet.header.originalLength, Timestamp: packetTimestamp.toISOString(), LinkLayerType: parser.linkLayerType !== undefined ? parser.linkLayerType : 1 }};
      let hexDump : string[] = [];
      try {
        const linkLayerType = detailedInfo["Frame Info"].LinkLayerType;
        let currentOffset = 0; 
        if (linkLayerType === 1 && packet.data && packet.data.length >= 14) { 
            const ethHeader = packet.data.slice(0, 14); detailedInfo["Ethernet II"] = { DestinationMAC: ethHeader.slice(0,6).toString('hex').match(/.{1,2}/g)?.join(':'), SourceMAC: ethHeader.slice(6,12).toString('hex').match(/.{1,2}/g)?.join(':'), EtherType: `0x${ethHeader.readUInt16BE(12).toString(16)}` }; const etherType = ethHeader.readUInt16BE(12); currentOffset = 14; 
            if (etherType === 0x0800) { 
                protocol = "IPv4";
                if (packet.data.length >= currentOffset + 20) { 
                    const ipHeaderIHL = (packet.data[currentOffset] & 0x0F); const ipHeaderLength = ipHeaderIHL * 4;
                    if (packet.data.length >= currentOffset + ipHeaderLength) {
                        const ipHeader = packet.data.slice(currentOffset, currentOffset + ipHeaderLength); sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`; destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`; ttl = ipHeader[8]; const ipProtocolField = ipHeader[9]; detailedInfo["IPv4"] = { Version: (ipHeader[0] & 0xF0) >> 4, HeaderLength: ipHeaderLength, TypeOfService: `0x${ipHeader[1].toString(16)}`, TotalLength: ipHeader.readUInt16BE(2), Identification: `0x${ipHeader.readUInt16BE(4).toString(16)}`, Flags: `0x${ipHeader.readUInt16BE(6).toString(16).padStart(4,'0').substring(0,1)}`, FragmentOffset: ipHeader.readUInt16BE(6) & 0x1FFF, TTL: ttl, Protocol: ipProtocolField, HeaderChecksum: `0x${ipHeader.readUInt16BE(10).toString(16)}`, SourceAddress: sourceIp, DestinationAddress: destIp }; info = `IPv4 ${sourceIp} -> ${destIp}`; currentOffset += ipHeaderLength;
                        if (ipProtocolField === 1) { protocol = "ICMP"; info += ` (ICMP)`; if (packet.data.length >= currentOffset + 8) { const icmpHeader = packet.data.slice(currentOffset, currentOffset + 8); const icmpType = icmpHeader[0]; const icmpCode = icmpHeader[1]; detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode, Checksum: `0x${icmpHeader.readUInt16BE(2).toString(16)}`, IdentifierBE: icmpHeader.readUInt16BE(4), SequenceNumberBE: icmpHeader.readUInt16BE(6) }; info += ` Type ${icmpType} Code ${icmpCode}`; } else { info += " (Truncated ICMP)"; isError = true; errorType = "TruncatedICMP"; }}
                        else if (ipProtocolField === 6) { protocol = "TCP"; if (packet.data.length >= currentOffset + 20) { const tcpHeaderBasic = packet.data.slice(currentOffset, currentOffset + 20); sourcePort = tcpHeaderBasic.readUInt16BE(0); destPort = tcpHeaderBasic.readUInt16BE(2); tcpSeq = tcpHeaderBasic.readUInt32BE(4); tcpAck = tcpHeaderBasic.readUInt32BE(8); const dataOffsetByte = tcpHeaderBasic[12]; const tcpHeaderLength = ((dataOffsetByte & 0xF0) >> 4) * 4; const flagsByte = tcpHeaderBasic[13]; flags = []; if (flagsByte & 0x01) flags.push("FIN"); if (flagsByte & 0x02) flags.push("SYN"); if (flagsByte & 0x04) flags.push("RST"); if (flagsByte & 0x08) flags.push("PSH"); if (flagsByte & 0x10) flags.push("ACK"); if (flagsByte & 0x20) flags.push("URG"); windowSize = tcpHeaderBasic.readUInt16BE(14); const payloadLength = packet.header.capturedLength - (currentOffset + tcpHeaderLength); info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq}${flags.includes("ACK") ? ` Ack=${tcpAck}` : ''} Win=${windowSize} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["TCP"] = { SourcePort: sourcePort, DestinationPort: destPort, SequenceNumber: tcpSeq, AckNumber: flags.includes("ACK") ? tcpAck : undefined, HeaderLength: tcpHeaderLength, Flags: flags.join(', ') || "None", WindowSize: windowSize, Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`, UrgentPointer: tcpHeaderBasic.readUInt16BE(18) }; if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; } currentOffset += tcpHeaderLength;} else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; }}
                        else if (ipProtocolField === 17) { protocol = "UDP"; if (packet.data.length >= currentOffset + 8) { const udpHeader = packet.data.slice(currentOffset, currentOffset + 8); sourcePort = udpHeader.readUInt16BE(0); destPort = udpHeader.readUInt16BE(2); const udpLength = udpHeader.readUInt16BE(4); const payloadLength = udpLength - 8; info = `${sourcePort} → ${destPort} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["UDP"] = { SourcePort: sourcePort, DestinationPort: destPort, Length: udpLength, Checksum: `0x${udpHeader.readUInt16BE(6).toString(16)}` }; currentOffset += 8;} else { info = "UDP (Truncated Header)"; isError = true; errorType = "TruncatedUDP"; }}
                        else { protocol = `IPProto ${ipProtocolField}`; info = `IP Protocol ${ipProtocolField}`; }
                    } else { info = "IPv4 (Truncated IP Header)"; isError = true; errorType = "TruncatedIP_pcap"; }
                } else { info = "IPv4 (Short Packet)"; isError = true; errorType = "ShortIPPacket_pcap"; }
            } else if (etherType === 0x86DD) { protocol = "IPv6"; info = "IPv6 Packet"; detailedInfo["IPv6"] = { Payload: "IPv6 detail TBD" }; }
            else if (etherType === 0x0806) { protocol = "ARP"; info = "ARP Packet"; detailedInfo["ARP"] = { Payload: "ARP detail TBD" }; }
            else { protocol = `EtherType_0x${etherType.toString(16)}`; info = `Unknown EtherType 0x${etherType.toString(16)}`; }
        } else { info = "Non-Ethernet or too short"; protocol = `LinkType_${linkLayerType}`; }
        const maxHexDumpBytes = 64; const dataBufferForDump = packet.data || Buffer.alloc(0); const dataToDump = dataBufferForDump.slice(0, Math.min(dataBufferForDump.length, maxHexDumpBytes)); for (let i = 0; i < dataToDump.length; i += 16) { const slice = dataToDump.slice(i, i + 16); const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || ''; const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.'); hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`); }
      } catch(e: any) { info = `Error decoding: ${e.message}`; isError = true; errorType = "DecodingError_PcapParser"; }
      const finalPacketData = { id: packetCounter, timestamp: packetTimestamp.toISOString(), sourceIp, sourcePort, destIp, destPort, protocol, length: packet.header.capturedLength, info, flags, tcpSeq, tcpAck, windowSize, ttl, isError, errorType, hexDump, detailedInfo };
      parsedPackets.push(finalPacketData);
      if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") { /* ... (connection logic) ... */
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`; const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`; const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd; if (!connectionMap.has(connId)) { connectionMap.set(connId, { id: connId, sourceIp, sourcePort, destIp, destPort, protocol, state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp, hasErrors: isError, errorTypes: isError && errorType ? [errorType] : [] }); } else { const conn = connectionMap.get(connId); conn.packets.push(packetCounter); conn.endTime = finalPacketData.timestamp; if (isError && !conn.hasErrors) conn.hasErrors = true; if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType); if (protocol === "TCP") { if (flags.includes("RST")) conn.state = "RESET"; else if (flags.includes("FIN") && flags.includes("ACK")) conn.state = "FIN_ACK"; else if (flags.includes("FIN") && conn.state !== "RESET") conn.state = "FIN_WAIT"; else if (flags.includes("SYN") && flags.includes("ACK") && conn.state === "SYN_SENT") conn.state = "ESTABLISHED"; else if (flags.includes("SYN") && conn.state !== "ESTABLISHED" && conn.state !== "RESET") conn.state = "SYN_SENT"; } }
      }
      if (packetCounter >= MAX_PACKETS_FOR_UI_DISPLAY) { const connections = Array.from(connectionMap.values()); cleanupAndResolve({ packets: parsedPackets, connections }); }
    });
    parser.on('end', () => { if (promiseResolved) return; const connections = Array.from(connectionMap.values()); cleanupAndResolve({ packets: parsedPackets, connections }); });
    parser.on('error', (err: Error) => { cleanupAndReject(new Error(`PcapParser stream error: ${err.message}`)); });
    readablePcapStream.on('error', (err: Error) => { cleanupAndReject(new Error(`ReadablePcapStream error for PcapParser: ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[REVISIT_PCAP_PARSER] ReadableStream closed prematurely for ${analysisId}.`); const conns = Array.from(connectionMap.values()); cleanupAndResolve({ packets: parsedPackets, connections: conns }); }});
  });
}

// --- Fungsi Parsing PCAPNG dengan Diagnostik Lanjutan ---
async function parsePcapNgWithNewParser(fileUrl: string, fileName: string, analysisId: string): Promise<{ packets: any[], connections: any[] }> {
  const functionStartTime = Date.now();
  console.log(`[PCAPNG_PARSER_V4_DIAG] START Parsing ID: ${analysisId}, File: ${fileName}`);
  console.time(`[PCAPNG_PARSER_V4_DIAG_TOTAL_TIME]_ID-${analysisId}`);

  let pcapBuffer: Buffer;
  try { /* ... (download logic) ... */
    const pcapResponse = await fetch(fileUrl);
    if (!pcapResponse.ok || !pcapResponse.body) throw new Error(`Failed to download PCAPNG: ${pcapResponse.statusText}`);
    const arrayBuffer = await pcapResponse.arrayBuffer(); pcapBuffer = Buffer.from(arrayBuffer);
    console.log(`[PCAPNG_PARSER_V4_DIAG] Downloaded ${fileName} (${(pcapBuffer.length / (1024*1024)).toFixed(3)} MB)`);
  } catch (downloadError) { throw downloadError; }

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = new PCAPNGParser(); // PCAPNGParser instance

  const parsedPackets: any[] = [];
  let packetCounter = 0;
  const MAX_PACKETS_PCAPNG = 100; // Naikkan sedikit untuk melihat apakah ada paket yang masuk
  let promiseResolved = false;
  const connectionMap = new Map<string, any>();
  let currentInterfaceInfo: any = {};
  let blockCounter = 0;
  let dataEventCounter = 0;

  console.time(`[PCAPNG_PARSER_V4_DIAG_PARSING_INSTANCE]_ID-${analysisId}`);

  return new Promise((resolve, reject) => {
    const cleanupAndFinish = (status: "resolved" | "rejected", dataOrError: any) => {
      if (!promiseResolved) {
        promiseResolved = true;
        console.log(`[PCAPNG_PARSER_V4_DIAG] Cleanup & ${status} for ${analysisId}. Packets: ${packetCounter}, DataEvents: ${dataEventCounter}, Blocks: ${blockCounter}. Total Time: ${((Date.now() - functionStartTime)/1000).toFixed(2)}s`);
        console.timeEnd(`[PCAPNG_PARSER_V4_DIAG_PARSING_INSTANCE]_ID-${analysisId}`);
        console.timeEnd(`[PCAPNG_PARSER_V4_DIAG_TOTAL_TIME]_ID-${analysisId}`);
        
        // Hapus semua listener dari parser dan stream
        if (parser) parser.removeAllListeners();
        if (readablePcapStream) {
            readablePcapStream.unpipe(parser); // Selalu unpipe sebelum destroy
            if (!readablePcapStream.destroyed) readablePcapStream.destroy();
            readablePcapStream.removeAllListeners();
        }
        
        if (status === "resolved") resolve(dataOrError);
        else reject(dataOrError);
      }
    };

    // Tambahkan listener error pada stream sumber terlebih dahulu
    readablePcapStream.on('error', (err: Error) => {
      console.error(`[PCAPNG_PARSER_V4_DIAG] ReadableStream emitted ERROR for ${analysisId}:`, err.message);
      cleanupAndFinish("rejected", new Error(`ReadablePcapStream error: ${err.message}`));
    });
    readablePcapStream.on('close', () => { // Ini yang terpicu sebelumnya
      console.log(`[PCAPNG_PARSER_V4_DIAG] ReadableStream emitted CLOSE for ${analysisId}. Processed ${packetCounter} packets, ${dataEventCounter} data events, ${blockCounter} blocks.`);
      // Jika stream ditutup sebelum parser 'end', mungkin data belum lengkap
      // Kita tetap coba resolve dengan apa yang ada, tapi ini indikasi masalah
      if (!promiseResolved) {
          generateAndResolveConnections(true); // Tandai sebagai potentially premature
      }
    });
     readablePcapStream.on('end', () => {
      console.log(`[PCAPNG_PARSER_V4_DIAG] ReadableStream emitted END for ${analysisId}.`);
      // Biasanya parser.on('end') yang akan menangani resolve
    });


    readablePcapStream.pipe(parser);

    parser.on('block', (block: any) => {
        blockCounter++;
        console.log(`[PCAPNG_PARSER_V4_DIAG] Block ${blockCounter} type: ${block.type} for ${analysisId}`);
        if (block.type === 'InterfaceDescriptionBlock') {
            currentInterfaceInfo[block.interfaceId] = { name: block.options?.if_name, linkLayerType: block.linkLayerType, snapLength: block.snapLength };
            console.log(`[PCAPNG_PARSER_V4_DIAG] Interface Block ID ${block.interfaceId} LinkType ${block.linkLayerType}`);
        }
    });

    parser.on('data', (parsedPcapNgPacket: any) => {
      if (promiseResolved) return;
      dataEventCounter++;

      if (parsedPcapNgPacket.type !== 'EnhancedPacketBlock' && parsedPcapNgPacket.type !== 'PacketBlock') {
        console.log(`[PCAPNG_PARSER_V4_DIAG] Data event, but skipping block type: ${parsedPcapNgPacket.type} for ${analysisId}`);
        return;
      }
      if (!parsedPcapNgPacket.data) {
        console.warn(`[PCAPNG_PARSER_V4_DIAG] Packet block without data for ${analysisId}:`, parsedPcapNgPacket);
        return;
      }
      
      console.time(`[PCAPNG_PARSER_V4_DIAG_PACKET_PROC]_ID-${analysisId}_PKT-${packetCounter + 1}`);
      packetCounter++;
      
      const packetDataBuffer = parsedPcapNgPacket.data;
      // ... (sisa logika decoding paket sama seperti versi diagnostik sebelumnya) ...
      let timestampDate;
      if (parsedPcapNgPacket.timestampHigh !== undefined && parsedPcapNgPacket.timestampLow !== undefined) timestampDate = pcapNgTimestampToDate(parsedPcapNgPacket.timestampHigh, parsedPcapNgPacket.timestampLow);
      else if (parsedPcapNgPacket.timestampSeconds !== undefined) timestampDate = new Date(parsedPcapNgPacket.timestampSeconds * 1000 + (parsedPcapNgPacket.timestampMicroseconds || 0) / 1000);
      else timestampDate = new Date();
      const timestamp = timestampDate.toISOString();
      const capturedLength = parsedPcapNgPacket.capturedLength || packetDataBuffer.length;
      const originalLength = parsedPcapNgPacket.originalPacketLength || packetDataBuffer.length;
      const interfaceId = parsedPcapNgPacket.interfaceId || 0;
      const ifaceInfo = currentInterfaceInfo[interfaceId] || { name: `Interface ${interfaceId}`, linkLayerType: 1, snapLength: 65535 };
      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = "Raw Data";
      let sourcePort, destPort, tcpSeq, tcpAck, windowSize, ttl;
      let flags: string[] = []; let isError = false; let errorType;
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, CapturedLength: capturedLength, OriginalLength: originalLength, Timestamp: timestamp, InterfaceID: interfaceId, InterfaceName: ifaceInfo.name, LinkLayerType: ifaceInfo.linkLayerType }};
      let hexDump : string[] = [];
      const linkLayerType = ifaceInfo.linkLayerType;
        try { 
            if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >= 14) { 
                detailedInfo["Ethernet II"] = { DestinationMAC: packetDataBuffer.slice(0,6).toString('hex').match(/.{1,2}/g)?.join(':'), SourceMAC: packetDataBuffer.slice(6,12).toString('hex').match(/.{1,2}/g)?.join(':'), EtherType: `0x${packetDataBuffer.readUInt16BE(12).toString(16)}` }; 
                const etherType = packetDataBuffer.readUInt16BE(12); let currentOffset = 14;
                if (etherType === 0x0800) { 
                    protocol = "IPv4"; 
                    if (packetDataBuffer.length >= currentOffset + 20) { 
                        const ipHeaderIHL = (packetDataBuffer[currentOffset] & 0x0F); const ipHeaderLength = ipHeaderIHL * 4;
                        if (packetDataBuffer.length >= currentOffset + ipHeaderLength) {
                            const ipHeader = packetDataBuffer.slice(currentOffset, currentOffset + ipHeaderLength); sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`; destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`; ttl = ipHeader[8]; const ipProtocolField = ipHeader[9]; detailedInfo["IPv4"] = { Version: (ipHeader[0] & 0xF0) >> 4, HeaderLength: ipHeaderLength, TypeOfService: `0x${ipHeader[1].toString(16)}`, TotalLength: ipHeader.readUInt16BE(2), Identification: `0x${ipHeader.readUInt16BE(4).toString(16)}`, Flags: `0x${ipHeader.readUInt16BE(6).toString(16).padStart(4,'0').substring(0,1)}`, FragmentOffset: ipHeader.readUInt16BE(6) & 0x1FFF, TTL: ttl, Protocol: ipProtocolField, HeaderChecksum: `0x${ipHeader.readUInt16BE(10).toString(16)}`, SourceAddress: sourceIp, DestinationAddress: destIp }; info = `IPv4 ${sourceIp} -> ${destIp}`; currentOffset += ipHeaderLength; let transportProtocolName = `IPProto_${ipProtocolField}`;
                            if (ipProtocolField === 1) { protocol = "ICMP"; transportProtocolName = "ICMP"; info += ` (ICMP)`; if (packetDataBuffer.length >= currentOffset + 8) { const icmpHeader = packetDataBuffer.slice(currentOffset, currentOffset+8); const icmpType = icmpHeader[0]; const icmpCode = icmpHeader[1]; detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode, Checksum: `0x${icmpHeader.readUInt16BE(2).toString(16)}`, IdentifierBE: icmpHeader.readUInt16BE(4), SequenceNumberBE: icmpHeader.readUInt16BE(6)}; info += ` Type ${icmpType} Code ${icmpCode}`; } else { info += " (Truncated ICMP)"; isError = true; errorType = "TruncatedICMP"; }}
                            else if (ipProtocolField === 6) { protocol = "TCP"; transportProtocolName = "TCP"; if (packetDataBuffer.length >= currentOffset + 20) { const tcpHeaderBasic = packetDataBuffer.slice(currentOffset, currentOffset + 20); sourcePort = tcpHeaderBasic.readUInt16BE(0); destPort = tcpHeaderBasic.readUInt16BE(2); tcpSeq = tcpHeaderBasic.readUInt32BE(4); tcpAck = tcpHeaderBasic.readUInt32BE(8); const dataOffsetByte = tcpHeaderBasic[12]; const tcpHeaderLength = ((dataOffsetByte & 0xF0) >> 4) * 4; const flagsByte = tcpHeaderBasic[13]; flags = []; if (flagsByte & 0x01) flags.push("FIN"); if (flagsByte & 0x02) flags.push("SYN"); if (flagsByte & 0x04) flags.push("RST"); if (flagsByte & 0x08) flags.push("PSH"); if (flagsByte & 0x10) flags.push("ACK"); if (flagsByte & 0x20) flags.push("URG"); windowSize = tcpHeaderBasic.readUInt16BE(14); const payloadLength = capturedLength - (currentOffset + tcpHeaderLength); info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq}${flags.includes("ACK") ? ` Ack=${tcpAck}` : ''} Win=${windowSize} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["TCP"] = { SourcePort: sourcePort, DestinationPort: destPort, SequenceNumber: tcpSeq, AckNumber: flags.includes("ACK") ? tcpAck : undefined, HeaderLength: tcpHeaderLength, Flags: flags.join(', ') || "None", WindowSize: windowSize, Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`, UrgentPointer: tcpHeaderBasic.readUInt16BE(18) }; if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; } currentOffset += tcpHeaderLength;} else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; }}
                            else if (ipProtocolField === 17) { protocol = "UDP"; transportProtocolName = "UDP"; if (packetDataBuffer.length >= currentOffset + 8) { const udpHeader = packetDataBuffer.slice(currentOffset, currentOffset + 8); sourcePort = udpHeader.readUInt16BE(0); destPort = udpHeader.readUInt16BE(2); const udpLength = udpHeader.readUInt16BE(4); const payloadLength = udpLength - 8; info = `${sourcePort} → ${destPort} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["UDP"] = { SourcePort: sourcePort, DestinationPort: destPort, Length: udpLength, Checksum: `0x${udpHeader.readUInt16BE(6).toString(16)}` }; currentOffset += 8;} else { info = "UDP (Truncated Header)"; isError = true; errorType = "TruncatedUDP"; }}
                            else { protocol = transportProtocolName; info = `IP Protocol ${ipProtocolField}`; }
                        } else { info = "IPv4 (Truncated IP Header)"; isError = true; errorType = "TruncatedIP"; }
                    } else { info = "IPv4 (Short Packet)"; isError = true; errorType = "ShortIPPacket"; }
                } else if (etherType === 0x86DD) { protocol = "IPv6"; info = "IPv6 Packet"; detailedInfo["IPv6"] = { Payload: "IPv6 detail TBD" }; }
                else if (etherType === 0x0806) { protocol = "ARP"; info = "ARP Packet"; detailedInfo["ARP"] = { Payload: "ARP detail TBD" }; }
                else { protocol = `UnknownEtherType_0x${etherType.toString(16)}`; info = `Unknown EtherType 0x${etherType.toString(16)}`; }
            } else if (linkLayerType !==1) { protocol = `LinkType_${linkLayerType}`; info = `Packet with Link Layer Type ${linkLayerType}`; detailedInfo[protocol] = { DataLength: packetDataBuffer.length }; }
            else { info = "Packet too short for Ethernet"; isError = true; errorType = "ShortPacketOrUnknownLink"; }
            const maxHexDumpBytes = 64; const dataToDump = packetDataBuffer || Buffer.alloc(0); const actualDataToDump = dataToDump.slice(0, Math.min(dataToDump.length, maxHexDumpBytes)); for (let i = 0; i < actualDataToDump.length; i += 16) { const slice = actualDataToDump.slice(i, i + 16); const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || ''; const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.'); hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`); }
        } catch(e: any) { info = `Error decoding: ${e.message}`; isError = true; errorType = "DecodingError_PcapNgParser"; }
      
      const finalPacketData = { id: packetCounter, timestamp, sourceIp, sourcePort, destIp, destPort, protocol, length: capturedLength, info, flags, tcpSeq, tcpAck, windowSize, ttl, isError, errorType, hexDump, detailedInfo };
      parsedPackets.push(finalPacketData);
      // ... (logika koneksi) ...
        if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") { const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`; const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`; const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd; if (!connectionMap.has(connId)) { connectionMap.set(connId, { id: connId, sourceIp, sourcePort, destIp, destPort, protocol, state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp, hasErrors: isError, errorTypes: isError && errorType ? [errorType] : [] }); } else { const conn = connectionMap.get(connId); conn.packets.push(packetCounter); conn.endTime = finalPacketData.timestamp; if (isError && !conn.hasErrors) conn.hasErrors = true; if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType); if (protocol === "TCP") { if (flags.includes("RST")) conn.state = "RESET"; else if (flags.includes("FIN") && flags.includes("ACK")) conn.state = "FIN_ACK"; else if (flags.includes("FIN") && conn.state !== "RESET") conn.state = "FIN_WAIT"; else if (flags.includes("SYN") && flags.includes("ACK") && conn.state === "SYN_SENT") conn.state = "ESTABLISHED"; else if (flags.includes("SYN") && conn.state !== "ESTABLISHED" && conn.state !== "RESET") conn.state = "SYN_SENT"; } } }

      console.timeEnd(`[PCAPNG_PARSER_V4_DIAG_PACKET_PROC]_ID-${analysisId}_PKT-${packetCounter}`);
      if (packetCounter % 10 === 0) console.log(`[PCAPNG_PARSER_V4_DIAG] Processed packet ${packetCounter} (data event ${dataEventCounter}) for ${analysisId}.`);

      if (packetCounter >= MAX_PACKETS_PCAPNG) {
        console.warn(`[PCAPNG_PARSER_V4_DIAG] Reached packet processing limit (${MAX_PACKETS_PCAPNG}) for ${analysisId}.`);
        generateAndResolveConnections(); 
      }
    }); 
    
    const generateAndResolveConnections = (premature: boolean = false) => {
        if (promiseResolved) return; 
        const connections = Array.from(connectionMap.values());
        if (premature) {
            console.warn(`[PCAPNG_PARSER_V4_DIAG] Resolving prematurely for ${analysisId} due to stream close. Packets: ${packetCounter}, Connections: ${connections.length}`);
        }
        cleanupAndFinish("resolved", { packets: parsedPackets, connections });
    };
    
    parser.on('end', () => {
      if (promiseResolved) return;
      console.log(`[PCAPNG_PARSER_V4_DIAG] Parser emitted END for ${analysisId}. Blocks: ${blockCounter}, DataEvents: ${dataEventCounter}, Packets: ${packetCounter}.`);
      generateAndResolveConnections();
    });

    parser.on('error', (err: Error) => {
      if (promiseResolved) return;
      console.error(`[PCAPNG_PARSER_V4_DIAG] Parser emitted ERROR for ${analysisId}:`, err.message);
      cleanupAndFinish("rejected", new Error(`PCAPNGParser stream error: ${err.message}`));
    });
  }); 
}

// --- Fungsi GET Utama dengan Logika Pemilihan Parser ---
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const VERCEL_TIMEOUT_SAFETY_MARGIN = 5000; 
  const functionTimeout = (process.env.VERCEL_FUNCTION_MAX_DURATION ? parseInt(process.env.VERCEL_FUNCTION_MAX_DURATION) * 1000 : 10000) - VERCEL_TIMEOUT_SAFETY_MARGIN; 
  const overallStartTime = Date.now();
  let timeoutId: NodeJS.Timeout | null = null;
  const analysisIdFromParams = params.id;

  const clearRaceTimeout = () => { if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; } };

  try {
    if (!analysisIdFromParams) {
      return NextResponse.json({ error: "Analysis ID is required in path" }, { status: 400 });
    }
    console.log(`[API_GET_PACKET_DATA_ROUTER_V4] Request for ${analysisIdFromParams}. Max exec ~${functionTimeout / 1000}s.`);
    
    const operationPromise = async () => {
        const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromParams });
        if (!pcapRecord) throw new Error("PCAP metadata not found (DB).");
        if (!pcapRecord.blobUrl) throw new Error("PCAP file URL not found (DB).");

        let pcapDataResult;
        const fileName = pcapRecord.originalName || pcapRecord.fileName || "unknown_file";

        if (fileName.toLowerCase().endsWith(".pcapng")) {
          console.log(`[API_GET_PACKET_DATA_ROUTER_V4] Using PCAPNG_PARSER for ${fileName}`);
          pcapDataResult = await parsePcapNgWithNewParser(pcapRecord.blobUrl, fileName, analysisIdFromParams);
        } else if (fileName.toLowerCase().endsWith(".pcap")) {
          console.log(`[API_GET_PACKET_DATA_ROUTER_V4] Using ORIGINAL_PARSER for ${fileName}`);
          pcapDataResult = await parsePcapWithOriginalParser(pcapRecord.blobUrl, fileName, analysisIdFromParams);
        } else {
          console.warn(`[API_GET_PACKET_DATA_ROUTER_V4] Unknown extension: ${fileName}. Defaulting to PCAPNG_PARSER.`);
          pcapDataResult = await parsePcapNgWithNewParser(pcapRecord.blobUrl, fileName, analysisIdFromParams);
        }
        return NextResponse.json({ success: true, ...pcapDataResult });
    };
    
    const overallTimeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        console.warn(`[API_GET_PACKET_DATA_ROUTER_V4] Overall GET timeout for ${analysisIdFromParams}.`);
        reject(new Error(`Operation timed out after ~${functionTimeout/1000}s.`));
      }, functionTimeout);
    });
    
    const response = await Promise.race([operationPromise(), overallTimeoutPromise]);
    clearRaceTimeout();
    
    console.log(`[API_GET_PACKET_DATA_ROUTER_V4] Finished for ${analysisIdFromParams}. Total GET time: ${((Date.now() - overallStartTime) / 1000).toFixed(2)}s`);
    return response as NextResponse;

  } catch (error) {
    clearRaceTimeout();
    const totalErrorTime = Date.now() - overallStartTime;
    console.error(`[API_GET_PACKET_DATA_ROUTER_V4] Error in GET for ${analysisIdFromParams}. Total time: ${(totalErrorTime / 1000).toFixed(2)}s. Error:`, error);
    const errorMessage = error instanceof Error ? error.message : "Failed to fetch packet data";
    const isTimeoutError = errorMessage.includes("timeout") || errorMessage.includes("aborted");
    return NextResponse.json({ 
        success: false, 
        error: isTimeoutError ? "Operation timed out." : errorMessage,
        details: error instanceof Error ? error.stack : "No stack",
        errorCode: isTimeoutError ? "TIMEOUT_ERROR" : "PARSING_ERROR"
    }, { status: 500 });
  }
}
