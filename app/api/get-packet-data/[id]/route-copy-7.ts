// app/api/get-packet-data/[id]/route.ts
import { type NextRequest, NextResponse } from "next/server";
import db from "@/lib/neon-db"; ///route.ts]
const PcapParser = require('pcap-parser'); // Parser lama untuk .pcap ///route.ts]
const PCAPNGParser = require('pcap-ng-parser'); // Parser baru untuk .pcapng ///route.ts]
import { Readable } from 'stream'; ///route.ts]

// --- Fungsi Helper Timestamp untuk PCAPNGParser ---
function pcapNgTimestampToDate(timestampHigh: number, timestampLow: number): Date { ///route.ts]
  // PCAPNG timestamps are typically 64-bit.
  // The unit can vary based on if_tsresol option in Interface Description Block.
  // Default resolution is 10^-6 (microseconds).
  // JavaScript's Date uses milliseconds.
  const tsresolOption = 6; // Default to microseconds if not specified in IDB
  const divisor = BigInt(10 ** (tsresolOption - 3)); // To convert to milliseconds

  const timestampBigInt = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
  try {
    const milliseconds = timestampBigInt / divisor;
    return new Date(Number(milliseconds));
  } catch (e) {
    console.warn(`[PCAPNG_TIMESTAMP_CONV_ERROR] Failed to convert timestamp: High=${timestampHigh}, Low=${timestampLow}, Divisor=${divisor}. Error: ${e}`);
    // Fallback to trying to treat low part as ms if high is 0 (very unlikely for real pcapng)
    if (timestampHigh === 0 && timestampLow > 0) {
        return new Date(timestampLow);
    }
    return new Date(); // Fallback to current time if conversion fails badly
  }
}

// --- Fungsi Parsing menggunakan PcapParser (Parser Lama untuk .pcap) ---
async function parsePcapWithOriginalParser(fileUrl: string, fileName: string, analysisId: string): Promise<{ packets: any[], connections: any[] }> { ///route.ts]
  console.log(`[REVISIT_PCAP_PARSER] Parsing .pcap: ${fileName} (ID: ${analysisId})`); ///route.ts]
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl); ///route.ts]
  if (!pcapResponse.ok || !pcapResponse.body) { ///route.ts]
    throw new Error(`[REVISIT_PCAP_PARSER] Failed to download .pcap file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer(); ///route.ts]
  const pcapBuffer = Buffer.from(arrayBuffer); ///route.ts]
  console.log(`[REVISIT_PCAP_PARSER] Downloaded ${fileName} in ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`); ///route.ts]

  const readablePcapStream = Readable.from(pcapBuffer); ///route.ts]
  const parser = PcapParser.parse(readablePcapStream); ///route.ts]

  const parsedPackets: any[] = []; ///route.ts]
  let packetCounter = 0; ///route.ts]
  const MAX_PACKETS_FOR_UI_DISPLAY = 500; ///route.ts]
  let promiseResolved = false; ///route.ts]
  const connectionMap = new Map<string, any>(); ///route.ts]

  return new Promise((resolve, reject) => { ///route.ts]
    const cleanupAndResolve = (data: { packets: any[], connections: any[] }) => { ///route.ts]
      if (!promiseResolved) { ///route.ts]
        promiseResolved = true; ///route.ts]
        console.log(`[REVISIT_PCAP_PARSER] Resolving for ${analysisId}. Packets: ${packetCounter}. Total time: ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`); ///route.ts]
        if (parser) parser.removeAllListeners(); ///route.ts]
        if (readablePcapStream && !readablePcapStream.destroyed) { ///route.ts]
          readablePcapStream.unpipe(parser);  ///route.ts]
          readablePcapStream.destroy(); ///route.ts]
        }
        resolve(data); ///route.ts]
      }
    };
    const cleanupAndReject = (error: Error) => { ///route.ts]
      if (!promiseResolved) { ///route.ts]
        promiseResolved = true; ///route.ts]
        console.error(`[REVISIT_PCAP_PARSER] Rejecting for ${analysisId}. Error: ${error.message}`); ///route.ts]
        if (parser) parser.removeAllListeners(); ///route.ts]
        if (readablePcapStream && !readablePcapStream.destroyed) { ///route.ts]
          readablePcapStream.unpipe(parser); ///route.ts]
          readablePcapStream.destroy(); ///route.ts]
        }
        reject(error); ///route.ts]
      }
    };

    parser.on('packet', (packet: any) => { ///route.ts]
      if (promiseResolved) return; ///route.ts]
      packetCounter++; ///route.ts]

      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = "Raw Data"; ///route.ts]
      let sourcePort: number | undefined, destPort: number | undefined, tcpSeq: number | undefined, tcpAck: number | undefined, windowSize: number | undefined, ttl: number | undefined; ///route.ts]
      let flags: string[] = []; let isError = false; let errorType: string | undefined; ///route.ts]
      const packetTimestamp = new Date(packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000); ///route.ts]
      let detailedInfo: any = {  ///route.ts]
        "Frame Info": { 
          Number: packetCounter, 
          CapturedLength: packet.header.capturedLength, 
          OriginalLength: packet.header.originalLength, 
          Timestamp: packetTimestamp.toISOString(),
          LinkLayerType: parser.linkLayerType !== undefined ? parser.linkLayerType : 1
        }
      };
      let hexDump : string[] = []; ///route.ts]

      try { ///route.ts]
        const linkLayerType = detailedInfo["Frame Info"].LinkLayerType; ///route.ts]
        let currentOffset = 0; 

        if (linkLayerType === 1 && packet.data && packet.data.length >= 14) { // Ethernet II ///route.ts]
            const ethHeader = packet.data.slice(0, 14); ///route.ts]
            detailedInfo["Ethernet II"] = { ///route.ts]
                DestinationMAC: ethHeader.slice(0,6).toString('hex').match(/.{1,2}/g)?.join(':'), ///route.ts]
                SourceMAC: ethHeader.slice(6,12).toString('hex').match(/.{1,2}/g)?.join(':'), ///route.ts]
                EtherType: `0x${ethHeader.readUInt16BE(12).toString(16)}` ///route.ts]
            };
            const etherType = ethHeader.readUInt16BE(12); ///route.ts]
            currentOffset = 14; 

            if (etherType === 0x0800) { // IPv4 ///route.ts]
                protocol = "IPv4"; ///route.ts]
                if (packet.data.length >= currentOffset + 20) {  ///route.ts]
                    const ipHeaderIHL = (packet.data[currentOffset] & 0x0F); ///route.ts]
                    const ipHeaderLength = ipHeaderIHL * 4; ///route.ts]
                    if (packet.data.length >= currentOffset + ipHeaderLength) { ///route.ts]
                        const ipHeader = packet.data.slice(currentOffset, currentOffset + ipHeaderLength); ///route.ts]
                        sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`; ///route.ts]
                        destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`; ///route.ts]
                        ttl = ipHeader[8]; ///route.ts]
                        const ipProtocolField = ipHeader[9]; ///route.ts]
                        detailedInfo["IPv4"] = { ///route.ts]
                            Version: (ipHeader[0] & 0xF0) >> 4, HeaderLength: ipHeaderLength, TypeOfService: `0x${ipHeader[1].toString(16)}`, TotalLength: ipHeader.readUInt16BE(2), Identification: `0x${ipHeader.readUInt16BE(4).toString(16)}`, Flags: `0x${ipHeader.readUInt16BE(6).toString(16).padStart(4,'0').substring(0,1)}`, FragmentOffset: ipHeader.readUInt16BE(6) & 0x1FFF, TTL: ttl, Protocol: ipProtocolField, HeaderChecksum: `0x${ipHeader.readUInt16BE(10).toString(16)}`, SourceAddress: sourceIp, DestinationAddress: destIp };
                        info = `IPv4 ${sourceIp} -> ${destIp}`; ///route.ts]
                        currentOffset += ipHeaderLength; ///route.ts]

                        if (ipProtocolField === 1) { // ICMP ///route.ts]
                            protocol = "ICMP"; info += ` (ICMP)`; ///route.ts]
                            if (packet.data.length >= currentOffset + 8) { const icmpHeader = packet.data.slice(currentOffset, currentOffset + 8); const icmpType = icmpHeader[0]; const icmpCode = icmpHeader[1]; detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode, Checksum: `0x${icmpHeader.readUInt16BE(2).toString(16)}`, IdentifierBE: icmpHeader.readUInt16BE(4), SequenceNumberBE: icmpHeader.readUInt16BE(6) }; info += ` Type ${icmpType} Code ${icmpCode}`; } else { info += " (Truncated ICMP)"; isError = true; errorType = "TruncatedICMP"; } ///route.ts]
                        }
                        else if (ipProtocolField === 6) { // TCP ///route.ts]
                            protocol = "TCP"; ///route.ts]
                            if (packet.data.length >= currentOffset + 20) { const tcpHeaderBasic = packet.data.slice(currentOffset, currentOffset + 20); sourcePort = tcpHeaderBasic.readUInt16BE(0); destPort = tcpHeaderBasic.readUInt16BE(2); tcpSeq = tcpHeaderBasic.readUInt32BE(4); tcpAck = tcpHeaderBasic.readUInt32BE(8); const dataOffsetByte = tcpHeaderBasic[12]; const tcpHeaderLength = ((dataOffsetByte & 0xF0) >> 4) * 4; const flagsByte = tcpHeaderBasic[13]; flags = []; if (flagsByte & 0x01) flags.push("FIN"); if (flagsByte & 0x02) flags.push("SYN"); if (flagsByte & 0x04) flags.push("RST"); if (flagsByte & 0x08) flags.push("PSH"); if (flagsByte & 0x10) flags.push("ACK"); if (flagsByte & 0x20) flags.push("URG"); windowSize = tcpHeaderBasic.readUInt16BE(14); const payloadLength = packet.header.capturedLength - (currentOffset + tcpHeaderLength); info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq}${flags.includes("ACK") ? ` Ack=${tcpAck}` : ''} Win=${windowSize} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["TCP"] = { SourcePort: sourcePort, DestinationPort: destPort, SequenceNumber: tcpSeq, AckNumber: flags.includes("ACK") ? tcpAck : undefined, HeaderLength: tcpHeaderLength, Flags: flags.join(', ') || "None", WindowSize: windowSize, Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`, UrgentPointer: tcpHeaderBasic.readUInt16BE(18) }; if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; } currentOffset += tcpHeaderLength;} else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; } ///route.ts]
                        }
                        else if (ipProtocolField === 17) { // UDP ///route.ts]
                             protocol = "UDP"; ///route.ts]
                             if (packet.data.length >= currentOffset + 8) { const udpHeader = packet.data.slice(currentOffset, currentOffset + 8); sourcePort = udpHeader.readUInt16BE(0); destPort = udpHeader.readUInt16BE(2); const udpLength = udpHeader.readUInt16BE(4); const payloadLength = udpLength - 8; info = `${sourcePort} → ${destPort} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["UDP"] = { SourcePort: sourcePort, DestinationPort: destPort, Length: udpLength, Checksum: `0x${udpHeader.readUInt16BE(6).toString(16)}` }; currentOffset += 8;} else { info = "UDP (Truncated Header)"; isError = true; errorType = "TruncatedUDP"; } ///route.ts]
                        }
                        else { protocol = `IPProto ${ipProtocolField}`; info = `IP Protocol ${ipProtocolField}`; } ///route.ts]
                    } else { info = "IPv4 (Truncated IP Header)"; isError = true; errorType = "TruncatedIP_pcap"; } ///route.ts]
                } else { info = "IPv4 (Short Packet)"; isError = true; errorType = "ShortIPPacket_pcap"; } ///route.ts]
            } else if (etherType === 0x86DD) { protocol = "IPv6"; info = "IPv6 Packet"; detailedInfo["IPv6"] = { Payload: "IPv6 detail TBD" }; } ///route.ts]
            else if (etherType === 0x0806) { protocol = "ARP"; info = "ARP Packet"; detailedInfo["ARP"] = { Payload: "ARP detail TBD" }; } ///route.ts]
            else { protocol = `EtherType_0x${etherType.toString(16)}`; info = `Unknown EtherType 0x${etherType.toString(16)}`; } ///route.ts]
        } else { info = "Non-Ethernet or too short"; protocol = `LinkType_${linkLayerType}`; } ///route.ts]
        
        const maxHexDumpBytes = 64; const dataBufferForDump = packet.data || Buffer.alloc(0); const dataToDump = dataBufferForDump.slice(0, Math.min(dataBufferForDump.length, maxHexDumpBytes)); ///route.ts]
        for (let i = 0; i < dataToDump.length; i += 16) { const slice = dataToDump.slice(i, i + 16); const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || ''; const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.'); hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`); } ///route.ts]

      } catch(e: any) { ///route.ts]
        console.warn(`[REVISIT_PCAP_PARSER] Error decoding packet ${packetCounter} (ID: ${analysisId}): ${e.message}`); ///route.ts]
        info = `Error decoding: ${e.message}`; isError = true; errorType = "DecodingError_PcapParser"; ///route.ts]
      }

      const finalPacketData = { id: packetCounter, timestamp: packetTimestamp.toISOString(), sourceIp, sourcePort, destIp, destPort, protocol, length: packet.header.capturedLength, info, flags, tcpSeq, tcpAck, windowSize, ttl, isError, errorType, hexDump, detailedInfo }; ///route.ts]
      parsedPackets.push(finalPacketData); ///route.ts]

      if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") { ///route.ts]
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`; const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`; const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd; ///route.ts]
          if (!connectionMap.has(connId)) { connectionMap.set(connId, { id: connId, sourceIp, sourcePort, destIp, destPort, protocol, state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp, hasErrors: isError, errorTypes: isError && errorType ? [errorType] : [] }); } else { const conn = connectionMap.get(connId); conn.packets.push(packetCounter); conn.endTime = finalPacketData.timestamp; if (isError && !conn.hasErrors) conn.hasErrors = true; if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType); if (protocol === "TCP") { if (flags.includes("RST")) conn.state = "RESET"; else if (flags.includes("FIN") && flags.includes("ACK")) conn.state = "FIN_ACK"; else if (flags.includes("FIN") && conn.state !== "RESET") conn.state = "FIN_WAIT"; else if (flags.includes("SYN") && flags.includes("ACK") && conn.state === "SYN_SENT") conn.state = "ESTABLISHED"; else if (flags.includes("SYN") && conn.state !== "ESTABLISHED" && conn.state !== "RESET") conn.state = "SYN_SENT"; } } ///route.ts]
      }
      if (packetCounter >= MAX_PACKETS_FOR_UI_DISPLAY) { const connections = Array.from(connectionMap.values()); cleanupAndResolve({ packets: parsedPackets, connections }); } ///route.ts]
    });
    parser.on('end', () => { if (promiseResolved) return; const connections = Array.from(connectionMap.values()); cleanupAndResolve({ packets: parsedPackets, connections }); }); ///route.ts]
    parser.on('error', (err: Error) => { cleanupAndReject(new Error(`PcapParser stream error: ${err.message}`)); }); ///route.ts]
    readablePcapStream.on('error', (err: Error) => { cleanupAndReject(new Error(`ReadablePcapStream error for PcapParser: ${err.message}`)); }); ///route.ts]
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[REVISIT_PCAP_PARSER] ReadableStream closed prematurely for ${analysisId}.`); const conns = Array.from(connectionMap.values()); cleanupAndResolve({ packets: parsedPackets, connections: conns }); }}); ///route.ts]
  });
}

// --- Fungsi Parsing PCAPNG dengan Diagnostik Lanjutan ---
async function parsePcapNgWithNewParser(fileUrl: string, fileName: string, analysisId: string): Promise<{ packets: any[], connections: any[] }> { ///route.ts]
  const functionStartTime = Date.now();
  console.log(`[PCAPNG_PARSER_V5_DIAG] START Parsing ID: ${analysisId}, File: ${fileName}`); ///route.ts]
  
  let pcapBuffer: Buffer;
  try {
    console.time(`[PCAPNG_PARSER_V5_DIAG_DOWNLOAD]_ID-${analysisId}`); ///route.ts]
    const pcapResponse = await fetch(fileUrl); ///route.ts]
    if (!pcapResponse.ok || !pcapResponse.body) throw new Error(`Failed to download PCAPNG: ${pcapResponse.statusText}`); ///route.ts]
    const arrayBuffer = await pcapResponse.arrayBuffer(); pcapBuffer = Buffer.from(arrayBuffer); ///route.ts]
    console.timeEnd(`[PCAPNG_PARSER_V5_DIAG_DOWNLOAD]_ID-${analysisId}`); ///route.ts]
    console.log(`[PCAPNG_PARSER_V5_DIAG] Downloaded ${fileName} (${(pcapBuffer.length / (1024*1024)).toFixed(3)} MB)`); ///route.ts]
  } catch (downloadError) { throw downloadError; }

  const readablePcapStream = Readable.from(pcapBuffer); ///route.ts]
  const parser = new PCAPNGParser(); ///route.ts]

  const parsedPackets: any[] = []; ///route.ts]
  let packetCounter = 0; ///route.ts]
  const MAX_PACKETS_PCAPNG = 100; ///route.ts]
  let promiseResolved = false; ///route.ts]
  const connectionMap = new Map<string, any>(); ///route.ts]
  let currentInterfaceInfo: any = {}; ///route.ts]
  let blockCounter = 0; ///route.ts]
  let dataEventCounter = 0; ///route.ts]

  console.time(`[PCAPNG_PARSER_V5_DIAG_PARSING_INSTANCE]_ID-${analysisId}`); ///route.ts]

  return new Promise((resolve, reject) => { ///route.ts]
    const cleanupAndFinish = (status: "resolved" | "rejected", dataOrError: any) => { ///route.ts]
        if (!promiseResolved) { ///route.ts]
          promiseResolved = true; ///route.ts]
          const outcome = status === "resolved" ? "Resolve" : "Reject";
          console.log(`[PCAPNG_PARSER_V5_DIAG] Cleanup & ${outcome} for ${analysisId}. Packets: ${packetCounter}, DataEvents: ${dataEventCounter}, Blocks: ${blockCounter}. Total Time: ${((Date.now() - functionStartTime)/1000).toFixed(2)}s`); ///route.ts]
          console.timeEnd(`[PCAPNG_PARSER_V5_DIAG_PARSING_INSTANCE]_ID-${analysisId}`); ///route.ts]
          console.timeEnd(`[PCAPNG_PARSER_V5_DIAG_TOTAL_TIME]_ID-${analysisId}`); ///route.ts]
          if (parser) parser.removeAllListeners(); ///route.ts]
          if (readablePcapStream) { ///route.ts]
              readablePcapStream.unpipe(parser);  ///route.ts]
              if (!readablePcapStream.destroyed) readablePcapStream.destroy(); ///route.ts]
              readablePcapStream.removeAllListeners(); ///route.ts]
          }
          if (status === "resolved") resolve(dataOrError); ///route.ts]
          else reject(dataOrError); ///route.ts]
        }
    };

    readablePcapStream.on('error', (err: Error) => { cleanupAndFinish("rejected", new Error(`ReadablePcapStream error: ${err.message}`)); }); ///route.ts]
    readablePcapStream.on('close', () => {  ///route.ts]
        console.log(`[PCAPNG_PARSER_V5_DIAG] ReadableStream emitted CLOSE for ${analysisId}. Processed ${packetCounter} packets, ${dataEventCounter} data events, ${blockCounter} blocks.`); ///route.ts]
        if (!promiseResolved) { generateAndResolveConnections(true); } ///route.ts]
    });
    readablePcapStream.on('end', () => { console.log(`[PCAPNG_PARSER_V5_DIAG] ReadableStream emitted END for ${analysisId}.`);}); ///route.ts]

    readablePcapStream.pipe(parser); ///route.ts]

    parser.on('block', (block: any) => { ///route.ts]
        blockCounter++; ///route.ts]
        console.log(`[PCAPNG_PARSER_V5_DIAG] Block ${blockCounter} received. Type: ${block.type}, InterfaceID: ${block.interfaceId}, Length: ${block.length}`); ///route.ts]
        if (block.type === 'SectionHeaderBlock') { ///route.ts]
            console.log(`[PCAPNG_PARSER_V5_DIAG] SectionHeaderBlock options:`, block.options); ///route.ts]
        } else if (block.type === 'InterfaceDescriptionBlock') { ///route.ts]
            currentInterfaceInfo[block.interfaceId] = { name: block.options?.if_name, linkLayerType: block.linkLayerType, snapLength: block.snapLength, tsresol: block.options?.if_tsresol }; ///route.ts]
            console.log(`[PCAPNG_PARSER_V5_DIAG] Interface Block ID ${block.interfaceId} LinkType ${block.linkLayerType}, TSResol: ${block.options?.if_tsresol}`); ///route.ts]
        }
    });

    parser.on('data', (parsedPcapNgPacket: any) => { ///route.ts]
      if (promiseResolved) return; ///route.ts]
      dataEventCounter++; ///route.ts]
      
      console.log(`[PCAPNG_PARSER_V5_DIAG] Data event ${dataEventCounter} received. Packet Type: ${parsedPcapNgPacket.type}`); ///route.ts]
      if (!parsedPcapNgPacket.type || (parsedPcapNgPacket.type !== 'EnhancedPacketBlock' && parsedPcapNgPacket.type !== 'PacketBlock')) { ///route.ts]
        console.warn(`[PCAPNG_PARSER_V5_DIAG] Unexpected or undefined block type in 'data' event for ${analysisId}. Block content:`, JSON.stringify(parsedPcapNgPacket).substring(0, 500)); ///route.ts]
      }

      if (!parsedPcapNgPacket.data) { ///route.ts]
        console.warn(`[PCAPNG_PARSER_V5_DIAG] Packet block (type: ${parsedPcapNgPacket.type}) without data buffer for ${analysisId}. Skipping packet processing.`); ///route.ts]
        return;
      }
      
      packetCounter++; ///route.ts]
      console.time(`[PCAPNG_PARSER_V5_DIAG_PACKET_PROC]_ID-${analysisId}_PKT-${packetCounter}`); ///route.ts]
      
      const packetDataBuffer = parsedPcapNgPacket.data; ///route.ts]
      let timestampDate; ///route.ts]
      if (parsedPcapNgPacket.timestampHigh !== undefined && parsedPcapNgPacket.timestampLow !== undefined) timestampDate = pcapNgTimestampToDate(parsedPcapNgPacket.timestampHigh, parsedPcapNgPacket.timestampLow); ///route.ts]
      else if (parsedPcapNgPacket.timestampSeconds !== undefined) timestampDate = new Date(parsedPcapNgPacket.timestampSeconds * 1000 + (parsedPcapNgPacket.timestampMicroseconds || 0) / 1000); ///route.ts]
      else { timestampDate = new Date(); console.warn(`[PCAPNG_PARSER_V5_DIAG] Fallback timestamp for packet ${packetCounter}`); } ///route.ts]
      const timestamp = timestampDate.toISOString(); ///route.ts]
      const capturedLength = parsedPcapNgPacket.capturedLength || packetDataBuffer.length; ///route.ts]
      const originalLength = parsedPcapNgPacket.originalPacketLength || packetDataBuffer.length; ///route.ts]
      const interfaceId = parsedPcapNgPacket.interfaceId === undefined ? 0 : parsedPcapNgPacket.interfaceId; ///route.ts]
      const ifaceInfo = currentInterfaceInfo[interfaceId] || { name: `Interface ${interfaceId}`, linkLayerType: 1, snapLength: 65535, tsresol: 6 }; ///route.ts]
      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = "Raw Data"; ///route.ts]
      let sourcePort, destPort, tcpSeq, tcpAck, windowSize, ttl; ///route.ts]
      let flags: string[] = []; let isError = false; let errorType; ///route.ts]
      let detailedInfo: any = { "Frame Info": { Number: packetCounter, CapturedLength: capturedLength, OriginalLength: originalLength, Timestamp: timestamp, InterfaceID: interfaceId, InterfaceName: ifaceInfo.name, LinkLayerType: ifaceInfo.linkLayerType }}; ///route.ts]
      let hexDump : string[] = []; ///route.ts]
      const linkLayerType = ifaceInfo.linkLayerType; ///route.ts]

      try {  ///route.ts]
          if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >= 14) {  ///route.ts]
              detailedInfo["Ethernet II"] = { DestinationMAC: packetDataBuffer.slice(0,6).toString('hex').match(/.{1,2}/g)?.join(':'), SourceMAC: packetDataBuffer.slice(6,12).toString('hex').match(/.{1,2}/g)?.join(':'), EtherType: `0x${packetDataBuffer.readUInt16BE(12).toString(16)}` };  ///route.ts]
              const etherType = packetDataBuffer.readUInt16BE(12); let currentOffset = 14; ///route.ts]
              if (etherType === 0x0800) {  ///route.ts]
                  protocol = "IPv4";  ///route.ts]
                  if (packetDataBuffer.length >= currentOffset + 20) {  ///route.ts]
                      const ipHeaderIHL = (packetDataBuffer[currentOffset] & 0x0F); const ipHeaderLength = ipHeaderIHL * 4; ///route.ts]
                      if (packetDataBuffer.length >= currentOffset + ipHeaderLength) { ///route.ts]
                          const ipHeader = packetDataBuffer.slice(currentOffset, currentOffset + ipHeaderLength); sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`; destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`; ttl = ipHeader[8]; const ipProtocolField = ipHeader[9]; detailedInfo["IPv4"] = { Version: (ipHeader[0] & 0xF0) >> 4, HeaderLength: ipHeaderLength, TypeOfService: `0x${ipHeader[1].toString(16)}`, TotalLength: ipHeader.readUInt16BE(2), Identification: `0x${ipHeader.readUInt16BE(4).toString(16)}`, Flags: `0x${ipHeader.readUInt16BE(6).toString(16).padStart(4,'0').substring(0,1)}`, FragmentOffset: ipHeader.readUInt16BE(6) & 0x1FFF, TTL: ttl, Protocol: ipProtocolField, HeaderChecksum: `0x${ipHeader.readUInt16BE(10).toString(16)}`, SourceAddress: sourceIp, DestinationAddress: destIp }; info = `IPv4 ${sourceIp} -> ${destIp}`; currentOffset += ipHeaderLength; let transportProtocolName = `IPProto_${ipProtocolField}`; ///route.ts]
                          if (ipProtocolField === 1) { protocol = "ICMP"; transportProtocolName = "ICMP"; info += ` (ICMP)`; if (packetDataBuffer.length >= currentOffset + 8) { const icmpHeader = packetDataBuffer.slice(currentOffset, currentOffset+8); const icmpType = icmpHeader[0]; const icmpCode = icmpHeader[1]; detailedInfo["ICMP"] = { Type: icmpType, Code: icmpCode, Checksum: `0x${icmpHeader.readUInt16BE(2).toString(16)}`, IdentifierBE: icmpHeader.readUInt16BE(4), SequenceNumberBE: icmpHeader.readUInt16BE(6)}; info += ` Type ${icmpType} Code ${icmpCode}`; } else { info += " (Truncated ICMP)"; isError = true; errorType = "TruncatedICMP"; }} ///route.ts]
                          else if (ipProtocolField === 6) { protocol = "TCP"; transportProtocolName = "TCP"; if (packetDataBuffer.length >= currentOffset + 20) { const tcpHeaderBasic = packetDataBuffer.slice(currentOffset, currentOffset + 20); sourcePort = tcpHeaderBasic.readUInt16BE(0); destPort = tcpHeaderBasic.readUInt16BE(2); tcpSeq = tcpHeaderBasic.readUInt32BE(4); tcpAck = tcpHeaderBasic.readUInt32BE(8); const dataOffsetByte = tcpHeaderBasic[12]; const tcpHeaderLength = ((dataOffsetByte & 0xF0) >> 4) * 4; const flagsByte = tcpHeaderBasic[13]; flags = []; if (flagsByte & 0x01) flags.push("FIN"); if (flagsByte & 0x02) flags.push("SYN"); if (flagsByte & 0x04) flags.push("RST"); if (flagsByte & 0x08) flags.push("PSH"); if (flagsByte & 0x10) flags.push("ACK"); if (flagsByte & 0x20) flags.push("URG"); windowSize = tcpHeaderBasic.readUInt16BE(14); const payloadLength = capturedLength - (currentOffset + tcpHeaderLength); info = `${sourcePort} → ${destPort} [${flags.join(', ')}] Seq=${tcpSeq}${flags.includes("ACK") ? ` Ack=${tcpAck}` : ''} Win=${windowSize} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["TCP"] = { SourcePort: sourcePort, DestinationPort: destPort, SequenceNumber: tcpSeq, AckNumber: flags.includes("ACK") ? tcpAck : undefined, HeaderLength: tcpHeaderLength, Flags: flags.join(', ') || "None", WindowSize: windowSize, Checksum: `0x${tcpHeaderBasic.readUInt16BE(16).toString(16)}`, UrgentPointer: tcpHeaderBasic.readUInt16BE(18) }; if (flags.includes("RST")) { isError = true; errorType = "TCP Reset"; } currentOffset += tcpHeaderLength;} else { info = "TCP (Truncated Header)"; isError = true; errorType = "TruncatedTCP"; }} ///route.ts]
                          else if (ipProtocolField === 17) { protocol = "UDP"; transportProtocolName = "UDP"; if (packetDataBuffer.length >= currentOffset + 8) { const udpHeader = packetDataBuffer.slice(currentOffset, currentOffset + 8); sourcePort = udpHeader.readUInt16BE(0); destPort = udpHeader.readUInt16BE(2); const udpLength = udpHeader.readUInt16BE(4); const payloadLength = udpLength - 8; info = `${sourcePort} → ${destPort} Len=${payloadLength >= 0 ? payloadLength : 0}`; detailedInfo["UDP"] = { SourcePort: sourcePort, DestinationPort: destPort, Length: udpLength, Checksum: `0x${udpHeader.readUInt16BE(6).toString(16)}` }; currentOffset += 8;} else { info = "UDP (Truncated Header)"; isError = true; errorType = "TruncatedUDP"; }} ///route.ts]
                          else { protocol = transportProtocolName; info = `IP Protocol ${ipProtocolField}`; } ///route.ts]
                      } else { info = "IPv4 (Truncated IP Header)"; isError = true; errorType = "TruncatedIP"; } ///route.ts]
                  } else { info = "IPv4 (Short Packet)"; isError = true; errorType = "ShortIPPacket"; } ///route.ts]
              } else if (etherType === 0x86DD) { protocol = "IPv6"; info = "IPv6 Packet"; detailedInfo["IPv6"] = { Payload: "IPv6 detail TBD" }; } ///route.ts]
              else if (etherType === 0x0806) { protocol = "ARP"; info = "ARP Packet"; detailedInfo["ARP"] = { Payload: "ARP detail TBD" }; } ///route.ts]
              else { protocol = `UnknownEtherType_0x${etherType.toString(16)}`; info = `Unknown EtherType 0x${etherType.toString(16)}`; } ///route.ts]
          } else if (linkLayerType !==1) { protocol = `LinkType_${linkLayerType}`; info = `Packet with Link Layer Type ${linkLayerType}`; detailedInfo[protocol] = { DataLength: packetDataBuffer.length }; } ///route.ts]
          else { info = "Packet too short for Ethernet"; isError = true; errorType = "ShortPacketOrUnknownLink"; } ///route.ts]
          const maxHexDumpBytes = 64; const dataToDump = packetDataBuffer || Buffer.alloc(0); const actualDataToDump = dataToDump.slice(0, Math.min(dataToDump.length, maxHexDumpBytes)); for (let i = 0; i < actualDataToDump.length; i += 16) { const slice = actualDataToDump.slice(i, i + 16); const hex = slice.toString('hex').match(/.{1,2}/g)?.join(' ') || ''; const ascii = slice.toString('ascii').replace(/[^\x20-\x7E]/g, '.'); hexDump.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(16*3-1)}  ${ascii}`); } ///route.ts]
      } catch(e: any) { info = `Error decoding: ${e.message}`; isError = true; errorType = "DecodingError_PcapNgParser"; } ///route.ts]
            
      const finalPacketData = { id: packetCounter, timestamp, sourceIp, sourcePort, destIp, destPort, protocol, length: capturedLength, info, flags, tcpSeq, tcpAck, windowSize, ttl, isError, errorType, hexDump, detailedInfo }; ///route.ts]
      parsedPackets.push(finalPacketData); ///route.ts]
      if ((protocol === "TCP" || protocol === "UDP") && sourcePort !== undefined && destPort !== undefined && sourceIp !== "N/A" && destIp !== "N/A") { /* ... logika koneksi ... */ ///route.ts]
          const connIdFwd = `${sourceIp}:${sourcePort}-${destIp}:${destPort}-${protocol}`; const connIdRev = `${destIp}:${destPort}-${sourceIp}:${sourcePort}-${protocol}`; const connId = connectionMap.has(connIdFwd) ? connIdFwd : connectionMap.has(connIdRev) ? connIdRev : connIdFwd; if (!connectionMap.has(connId)) { connectionMap.set(connId, { id: connId, sourceIp, sourcePort, destIp, destPort, protocol, state: protocol === "TCP" ? (flags.includes("SYN") ? "SYN_SENT" : "ACTIVE") : "ACTIVE", packets: [packetCounter], startTime: finalPacketData.timestamp, hasErrors: isError, errorTypes: isError && errorType ? [errorType] : [] }); } else { const conn = connectionMap.get(connId); conn.packets.push(packetCounter); conn.endTime = finalPacketData.timestamp; if (isError && !conn.hasErrors) conn.hasErrors = true; if (isError && errorType && !conn.errorTypes.includes(errorType)) conn.errorTypes.push(errorType); if (protocol === "TCP") { if (flags.includes("RST")) conn.state = "RESET"; else if (flags.includes("FIN") && flags.includes("ACK")) conn.state = "FIN_ACK"; else if (flags.includes("FIN") && conn.state !== "RESET") conn.state = "FIN_WAIT"; else if (flags.includes("SYN") && flags.includes("ACK") && conn.state === "SYN_SENT") conn.state = "ESTABLISHED"; else if (flags.includes("SYN") && conn.state !== "ESTABLISHED" && conn.state !== "RESET") conn.state = "SYN_SENT"; } } ///route.ts]
      }
      
      console.timeEnd(`[PCAPNG_PARSER_V5_DIAG_PACKET_PROC]_ID-${analysisId}_PKT-${packetCounter}`); ///route.ts]
      if (packetCounter % 10 === 0) console.log(`[PCAPNG_PARSER_V5_DIAG] Processed packet ${packetCounter} (data event ${dataEventCounter}) for ${analysisId}.`); ///route.ts]

      if (packetCounter >= MAX_PACKETS_PCAPNG) { ///route.ts]
        console.warn(`[PCAPNG_PARSER_V5_DIAG] Reached packet processing limit (${MAX_PACKETS_PCAPNG}) for ${analysisId}.`); ///route.ts]
        generateAndResolveConnections();  ///route.ts]
      }
    }); 
    
    const generateAndResolveConnections = (premature: boolean = false) => { ///route.ts]
        if (promiseResolved) return;  ///route.ts]
        const connections = Array.from(connectionMap.values()); ///route.ts]
        if (premature) { ///route.ts]
            console.warn(`[PCAPNG_PARSER_V5_DIAG] Resolving prematurely for ${analysisId}. Packets: ${packetCounter}, Connections: ${connections.length}`); ///route.ts]
        }
        cleanupAndFinish("resolved", { packets: parsedPackets, connections }); ///route.ts]
    };
    
    parser.on('end', () => {  ///route.ts]
        if (promiseResolved) return; ///route.ts]
        console.log(`[PCAPNG_PARSER_V5_DIAG] Parser emitted END for ${analysisId}. Blocks: ${blockCounter}, DataEvents: ${dataEventCounter}, Packets: ${packetCounter}.`); ///route.ts]
        generateAndResolveConnections(); ///route.ts]
    });
    parser.on('error', (err: Error) => {  ///route.ts]
        if (promiseResolved) return; ///route.ts]
        console.error(`[PCAPNG_PARSER_V5_DIAG] Parser emitted ERROR for ${analysisId}:`, err.message); ///route.ts]
        cleanupAndFinish("rejected", new Error(`PCAPNGParser stream error: ${err.message}`)); ///route.ts]
    });
  }); 
}


// --- Fungsi GET Utama dengan Logika Pemilihan Parser ---
export async function GET(request: NextRequest, { params }: { params: { id: string } }) { ///route.ts]
  const VERCEL_TIMEOUT_SAFETY_MARGIN = 5000;  ///route.ts]
  const functionTimeout = (process.env.VERCEL_FUNCTION_MAX_DURATION ? parseInt(process.env.VERCEL_FUNCTION_MAX_DURATION) * 1000 : 10000) - VERCEL_TIMEOUT_SAFETY_MARGIN;  ///route.ts]
  const overallStartTime = Date.now(); ///route.ts]
  let timeoutId: NodeJS.Timeout | null = null; ///route.ts]
  const analysisIdFromParams = params.id; ///route.ts]

  const clearRaceTimeout = () => { if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; } }; ///route.ts]

  try { ///route.ts]
    if (!analysisIdFromParams) { ///route.ts]
      return NextResponse.json({ error: "Analysis ID is required in path" }, { status: 400 }); ///route.ts]
    }
    console.log(`[API_GET_PACKET_DATA_ROUTER_V5] Request for ${analysisIdFromParams}. Max exec ~${functionTimeout / 1000}s.`); ///route.ts]
    
    const operationPromise = async () => { ///route.ts]
        const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromParams }); ///route.ts]
        if (!pcapRecord) throw new Error("PCAP metadata not found (DB)."); ///route.ts]
        if (!pcapRecord.blobUrl) throw new Error("PCAP file URL not found (DB)."); ///route.ts]

        let pcapDataResult;
        const fileName = pcapRecord.originalName || pcapRecord.fileName || "unknown_file"; ///route.ts]

        if (fileName.toLowerCase().endsWith(".pcapng")) { ///route.ts]
          console.log(`[API_GET_PACKET_DATA_ROUTER_V5] Using PCAPNG_PARSER for ${fileName}`); ///route.ts]
          pcapDataResult = await parsePcapNgWithNewParser(pcapRecord.blobUrl, fileName, analysisIdFromParams); ///route.ts]
        } else if (fileName.toLowerCase().endsWith(".pcap")) { ///route.ts]
          console.log(`[API_GET_PACKET_DATA_ROUTER_V5] Using ORIGINAL_PARSER for ${fileName}`); ///route.ts]
          pcapDataResult = await parsePcapWithOriginalParser(pcapRecord.blobUrl, fileName, analysisIdFromParams); ///route.ts]
        } else { ///route.ts]
          console.warn(`[API_GET_PACKET_DATA_ROUTER_V5] Unknown extension: ${fileName}. Defaulting to PCAPNG_PARSER.`); ///route.ts]
          pcapDataResult = await parsePcapNgWithNewParser(pcapRecord.blobUrl, fileName, analysisIdFromParams); ///route.ts]
        }
        return NextResponse.json({ success: true, ...pcapDataResult }); ///route.ts]
    };
    
    const overallTimeoutPromise = new Promise((_, reject) => { ///route.ts]
      timeoutId = setTimeout(() => { ///route.ts]
        console.warn(`[API_GET_PACKET_DATA_ROUTER_V5] Overall GET operation timeout for ${analysisIdFromParams}.`); ///route.ts]
        reject(new Error(`Operation timed out after ~${functionTimeout/1000} seconds.`)); ///route.ts]
      }, functionTimeout); ///route.ts]
    });
    
    const response = await Promise.race([operationPromise(), overallTimeoutPromise]); ///route.ts]
    clearRaceTimeout(); ///route.ts]
    
    console.log(`[API_GET_PACKET_DATA_ROUTER_V5] Finished for ${analysisIdFromParams}. Total GET time: ${((Date.now() - overallStartTime) / 1000).toFixed(2)}s`); ///route.ts]
    return response as NextResponse; ///route.ts]

  } catch (error) { ///route.ts]
    clearRaceTimeout(); ///route.ts]
    const totalErrorTime = Date.now() - overallStartTime; ///route.ts]
    console.error(`[API_GET_PACKET_DATA_ROUTER_V5] Error in GET for ${analysisIdFromParams}. Total time: ${(totalErrorTime / 1000).toFixed(2)}s. Error:`, error); ///route.ts]
    const errorMessage = error instanceof Error ? error.message : "Failed to fetch packet data"; ///route.ts]
    const isTimeoutError = errorMessage.includes("timeout") || errorMessage.includes("aborted"); ///route.ts]
    return NextResponse.json({  ///route.ts]
        success: false, 
        error: isTimeoutError ? "Operation timed out." : errorMessage, ///route.ts]
        details: error instanceof Error ? error.stack : "No stack", ///route.ts]
        errorCode: isTimeoutError ? "TIMEOUT_ERROR" : "PARSING_ERROR" ///route.ts]
    }, { status: 500 });
  }
}
