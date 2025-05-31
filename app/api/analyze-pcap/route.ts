// app/api/analyze-pcap/route-copy-7-fix terakhir.ts
import { type NextRequest, NextResponse } from "next/server";
import { generateText } from "ai";
import { createGroq } from "@ai-sdk/groq";
import db from "@/lib/neon-db";
const PcapParser = require('pcap-parser');
const PCAPNGParser = require('pcap-ng-parser');
import { Readable } from 'stream';

export const runtime = 'nodejs';
const MAX_SAMPLES_FOR_AI = 25; // Anda bisa sesuaikan jumlah sampel
const MAX_ERROR_INSTANCES_FOR_AI = 15; // Batasi jumlah instance error spesifik untuk AI
const MAX_PACKETS_TO_PROCESS_FOR_STATS = 5000;

// --- Fungsi Helper Timestamp ---
function getTimestamp(packetHeader: any, isPcapNg: boolean = false, pcapNgPacket?: any, ifaceInfo?: any): string {
    if (isPcapNg && pcapNgPacket) {
        let timestampDate;
        const tsresolRaw = ifaceInfo?.tsresol !== undefined ? Number(ifaceInfo.tsresol) : 6;
        const isPowerOf2 = (tsresolRaw & 0x80) !== 0;
        const tsresolValue = tsresolRaw & 0x7F;

        let divisorBigInt: BigInt;
        if (isPowerOf2) {
            // console.warn(`[AI_TIMESTAMP_CONV] Power-of-2 tsresol (${tsresolValue}) not fully implemented. Defaulting to microsecond logic.`);
            divisorBigInt = BigInt(10 ** (6 - 3));
        } else {
            divisorBigInt = BigInt(10 ** (Math.max(0, tsresolValue - 3)));
        }

        const timestampBigInt = (BigInt(pcapNgPacket.timestampHigh) << 32n) | BigInt(pcapNgPacket.timestampLow);
        try {
            if (tsresolValue < 3 && !isPowerOf2) {
                const multiplier = BigInt(10 ** (3 - tsresolValue));
                timestampDate = new Date(Number(timestampBigInt * multiplier));
            } else {
                if (divisorBigInt === 0n) divisorBigInt = 1n;
                const milliseconds = timestampBigInt / divisorBigInt;
                timestampDate = new Date(Number(milliseconds));
            }
        } catch (e) {
            console.warn(`[AI_TIMESTAMP_CONV_ERROR] pcapng: High=${pcapNgPacket.timestampHigh}, Low=${pcapNgPacket.timestampLow}, tsresolRaw=${tsresolRaw}. Error: ${e}`);
            timestampDate = new Date();
        }

        if (pcapNgPacket.timestampSeconds !== undefined && (pcapNgPacket.timestampHigh === undefined || pcapNgPacket.timestampLow === undefined)) {
            timestampDate = new Date(pcapNgPacket.timestampSeconds * 1000 + (pcapNgPacket.timestampMicroseconds || 0) / 1000);
        } else if (!timestampDate) {
            timestampDate = new Date();
            // console.warn(`[AI_TIMESTAMP_CONV] Final fallback timestamp for pcapng packet`);
        }
        return timestampDate.toISOString();
    } else {
        return new Date(packetHeader.timestampSeconds * 1000 + packetHeader.timestampMicroseconds / 1000).toISOString();
    }
}


// --- Parser untuk .pcap (menggunakan PcapParser) ---
async function parsePcapForAIWithOriginalParser(fileUrl: string, fileName: string, analysisId: string): Promise<any> {
  console.log(`[AI_ORIGINAL_PARSER_V5_VOIP_IMPROVED] Parsing .pcap for AI: ${fileName} (ID: ${analysisId})`);
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[AI_ORIGINAL_PARSER_V5_VOIP_IMPROVED] Failed to download .pcap file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = PcapParser.parse(readablePcapStream);

  let packetCounter = 0;
  const protocolStats: { [key: string]: number } = {};
  const samplePacketsForAI: Array<any> = [];
  let promiseResolved = false;
  const ipTraffic: { [ip: string]: { sentPackets: number, receivedPackets: number, sentBytes: number, receivedBytes: number, totalPackets: number, totalBytes: number } } = {};

  return new Promise((resolve, reject) => {
    const cleanupAndFinish = (status: "resolved" | "rejected", dataOrError: any) => {
      if (!promiseResolved) {
        promiseResolved = true;
        const outcome = status === "resolved" ? "Resolve" : "Reject";
        console.log(`[AI_ORIGINAL_PARSER_V5_VOIP_IMPROVED] Cleanup & ${outcome} for AI ${analysisId}. Packets: ${packetCounter}. Total time: ${((Date.now() - functionStartTime) / 1000).toFixed(2)}s`);
        if (parser) parser.removeAllListeners();
        if (readablePcapStream) {
            readablePcapStream.unpipe(parser);
            if (!readablePcapStream.destroyed) readablePcapStream.destroy();
            readablePcapStream.removeAllListeners();
        }
        if (status === "resolved") resolve(dataOrError); else reject(dataOrError);
      }
    };

    parser.on('packet', (packet: any) => {
      if (promiseResolved) return;
      packetCounter++;
      const packetLength = packet.header.capturedLength;
      const timestamp = getTimestamp(packet.header, false);

      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = `Len ${packetLength}`;
      let sourcePort: number | undefined, destPort: number | undefined;
      let isError = false, errorType: string | undefined = undefined;
      let flags: string[] = [];
      let payloadHexSample = "";
      let voipDetails: any = null;

      try {
        const linkLayerType = parser.linkLayerType !== undefined ? parser.linkLayerType : 1;
        let currentOffset = 0;
        if (linkLayerType === 1 && packet.data && packet.data.length >= 14) {
            const etherType = packet.data.readUInt16BE(12);
            currentOffset = 14;
            if (etherType === 0x0800) { // IPv4
                protocol = "IPv4";
                if (packet.data.length >= currentOffset + 20) {
                    const ipHeaderIHL = (packet.data[currentOffset] & 0x0F);
                    const ipHeaderLength = ipHeaderIHL * 4;
                    if (packet.data.length >= currentOffset + ipHeaderLength) {
                        const ipHeader = packet.data.slice(currentOffset, currentOffset + ipHeaderLength);
                        sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                        destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                        const ipProtocolField = ipHeader[9];
                        info = `IPv4 ${sourceIp} -> ${destIp}`;
                        currentOffset += ipHeaderLength;
                        let transportHeaderStart = currentOffset;

                        if (ipProtocolField === 1) { protocol = "ICMP"; info += ` ICMP`; }
                        else if (ipProtocolField === 6) {
                            protocol = "TCP";
                            if (packet.data.length >= currentOffset + 20) {
                                sourcePort = packet.data.readUInt16BE(currentOffset);
                                destPort = packet.data.readUInt16BE(currentOffset + 2);
                                const flagsByte = packet.data[currentOffset + 13];
                                const tcpHeaderLength = ((packet.data[currentOffset+12] & 0xF0) >> 4) * 4;
                                transportHeaderStart = currentOffset + tcpHeaderLength;

                                if (flagsByte & 0x04) { flags.push("RST"); isError = true; errorType = "TCP Reset"; }
                                if (flagsByte & 0x02) flags.push("SYN");
                                if (flagsByte & 0x01) flags.push("FIN");
                                if (flagsByte & 0x10) flags.push("ACK");
                                info = `${sourcePort} → ${destPort} [${flags.join(',')}] TCP`;

                                if (sourcePort === 5060 || destPort === 5060 || sourcePort === 5061 || destPort === 5061) {
                                    protocol = "SIP/TCP";
                                    if (packet.data.length > transportHeaderStart) payloadHexSample = packet.data.slice(transportHeaderStart).toString('hex').substring(0, 256);
                                    voipDetails = { signalingProtocol: "SIP", transport: "TCP" };
                                } else if (sourcePort === 2000 || destPort === 2000) {
                                    protocol = "SCCP/TCP";
                                    if (packet.data.length > transportHeaderStart) payloadHexSample = packet.data.slice(transportHeaderStart).toString('hex').substring(0, 128);
                                    voipDetails = { signalingProtocol: "SCCP", transport: "TCP" };
                                }
                            } else { isError = true; errorType = "TruncatedTCP_AI"; info += ` TCP (Truncated)`;}
                        }
                        else if (ipProtocolField === 17) {
                            protocol = "UDP";
                            if (packet.data.length >= currentOffset + 8) {
                                sourcePort = packet.data.readUInt16BE(currentOffset);
                                destPort = packet.data.readUInt16BE(currentOffset + 2);
                                transportHeaderStart = currentOffset + 8;
                                info = `${sourcePort} → ${destPort} UDP`;

                                if (sourcePort === 5060 || destPort === 5060) {
                                    protocol = "SIP/UDP";
                                    if (packet.data.length > transportHeaderStart) payloadHexSample = packet.data.slice(transportHeaderStart).toString('hex').substring(0, 256);
                                    voipDetails = { signalingProtocol: "SIP", transport: "UDP" };
                                } else if ((sourcePort >= 16384 && sourcePort <= 32767 && sourcePort % 2 === 0) || (destPort >= 16384 && destPort <= 32767 && destPort % 2 === 0) ) {
                                    protocol = "RTP/UDP";
                                    if (packet.data.length > transportHeaderStart + 12) payloadHexSample = packet.data.slice(transportHeaderStart + 12).toString('hex').substring(0, 48); // RTP Payload after 12B header
                                    voipDetails = { mediaProtocol: "RTP", transport: "UDP" };
                                } else if ((sourcePort >= 16384 && sourcePort <= 32767 && sourcePort % 2 !== 0) || (destPort >= 16384 && destPort <= 32767 && destPort % 2 !== 0) ) {
                                    protocol = "RTCP/UDP";
                                    if (packet.data.length > transportHeaderStart) payloadHexSample = packet.data.slice(transportHeaderStart).toString('hex').substring(0, 64);
                                    voipDetails = { mediaControlProtocol: "RTCP", transport: "UDP" };
                                }
                            } else { isError = true; errorType = "TruncatedUDP_AI"; info += ` UDP (Truncated)`;}
                        }
                        else { protocol = `IPProto ${ipProtocolField}`; }
                    } else { isError = true; errorType = "TruncatedIP_AI"; }
                } else { isError = true; errorType = "ShortIP_AI"; }
            } else if (etherType === 0x86DD) { protocol = "IPv6"; }
            else if (etherType === 0x0806) { protocol = "ARP"; }
            else { protocol = `EtherType_0x${etherType.toString(16)}`; }
        } else { protocol = `LinkType_${linkLayerType}`; }
      } catch (e: any) { info = `Decode Err: ${e.message}`; isError = true; errorType = "DecodingErrorPcapAI"; }

      protocolStats[protocol] = (protocolStats[protocol] || 0) + 1;
      if (sourceIp !== "N/A") { if (!ipTraffic[sourceIp]) ipTraffic[sourceIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[sourceIp].sentPackets++; ipTraffic[sourceIp].sentBytes += packetLength; ipTraffic[sourceIp].totalPackets++; ipTraffic[sourceIp].totalBytes += packetLength;}
      if (destIp !== "N/A") { if (!ipTraffic[destIp]) ipTraffic[destIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[destIp].receivedPackets++; ipTraffic[destIp].receivedBytes += packetLength; ipTraffic[destIp].totalPackets++; ipTraffic[destIp].totalBytes += packetLength;}

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < Math.floor(MAX_SAMPLES_FOR_AI / 2)) ) {
        samplePacketsForAI.push({ no: packetCounter, timestamp, source: sourceIp, destination: destIp, sourcePort, destPort, protocol, length: packetLength, info, isError, errorType, payloadHexSample: payloadHexSample || undefined, voipDetails: voipDetails || undefined });
      }
      if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) {
        cleanupAndFinish("resolved", prepareAiData());
      }
    });

    const prepareAiData = () => {
      const topProtocols = Object.entries(protocolStats).sort(([,a],[,b]) => b-a).slice(0, 7).reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});
      const calculatedTopTalkers = Object.entries(ipTraffic).map(([ip, data]) => ({ ip, packets: data.totalPackets, bytes: data.totalBytes, sentPackets:data.sentPackets, receivedPackets:data.receivedPackets, sentBytes:data.sentBytes, receivedBytes:data.receivedBytes })).sort((a, b) => b.bytes - a.bytes).slice(0, 7);
      return { statistics: { totalPacketsInFile: packetCounter, packetsProcessedForStats: packetCounter, protocols: topProtocols, topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "N/A", packets:0, bytes:0, sentPackets:0, receivedPackets:0, sentBytes:0, receivedBytes:0}], anomalyScore: Math.floor(Math.random() * 30) + 10, }, samplePackets: samplePacketsForAI };
    };

    parser.on('end', () => { if (!promiseResolved) cleanupAndFinish("resolved", prepareAiData()); });
    parser.on('error', (err: Error) => { if (!promiseResolved) cleanupAndFinish("rejected", new Error(`PcapParser stream error for AI: ${err.message}`)); });
    readablePcapStream.on('error', (err: Error) => { if (!promiseResolved) cleanupAndFinish("rejected", new Error(`ReadableStream error for PcapParser AI: ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[AI_ORIGINAL_PARSER_V5_VOIP_IMPROVED] ReadableStream closed prematurely for AI ${analysisId}.`); cleanupAndFinish("resolved", prepareAiData()); }});
  });
}

// --- Parser untuk .pcapng (menggunakan PCAPNGParser) ---
async function parsePcapFileForAIWithPcapNgParser(fileUrl: string, fileName: string, analysisId: string): Promise<any> {
  console.log(`[AI_PCAPNG_PARSER_V5_VOIP_IMPROVED] Parsing .pcapng for AI: ${fileName} (ID: ${analysisId})`);
  const functionStartTime = Date.now();

  const pcapResponse = await fetch(fileUrl);
  if (!pcapResponse.ok || !pcapResponse.body) {
    throw new Error(`[AI_PCAPNG_PARSER_V5_VOIP_IMPROVED] Failed to download .pcapng file: ${pcapResponse.statusText}`);
  }
  const arrayBuffer = await pcapResponse.arrayBuffer();
  const pcapBuffer = Buffer.from(arrayBuffer);

  const readablePcapStream = Readable.from(pcapBuffer);
  const parser = new PCAPNGParser();

  let packetCounter = 0;
  const protocolStats: { [key: string]: number } = {};
  const samplePacketsForAI: Array<any> = [];
  let promiseResolved = false;
  const ipTraffic: { [ip: string]: { sentPackets: number, receivedPackets: number, sentBytes: number, receivedBytes: number, totalPackets: number, totalBytes: number } } = {};
  let currentInterfaceInfo: any = {};
  let blockCounter = 0;
  let dataEventCounter = 0;

  return new Promise((resolve, reject) => {
    const cleanupAndFinish = (status: "resolved" | "rejected", dataOrError: any) => {
      if (!promiseResolved) { promiseResolved = true; const o=status==="resolved"?"Resolve":"Reject"; console.log(`[AI_PCAPNG_PARSER_V5_VOIP_IMPROVED] Cleanup & ${o} for ${analysisId}. Packets:${packetCounter}, DataEvents:${dataEventCounter}, Blocks:${blockCounter}. Time:${((Date.now()-functionStartTime)/1000).toFixed(2)}s`); if(parser)parser.removeAllListeners(); if(readablePcapStream){readablePcapStream.unpipe(parser); if(!readablePcapStream.destroyed)readablePcapStream.destroy(); readablePcapStream.removeAllListeners();} if(status==="resolved")resolve(dataOrError); else reject(dataOrError); }
    };
    readablePcapStream.on('error', (err: Error) => { cleanupAndFinish("rejected", new Error(`ReadableStream error (AI PcapNG): ${err.message}`)); });
    readablePcapStream.on('close', () => { if (!promiseResolved) { console.warn(`[AI_PCAPNG_PARSER_V5_VOIP_IMPROVED] ReadableStream closed prematurely for AI ${analysisId}.`); cleanupAndFinish("resolved", prepareAiData()); }});
    readablePcapStream.on('end', () => { console.log(`[AI_PCAPNG_PARSER_V5_VOIP_IMPROVED] ReadableStream END for AI ${analysisId}.`);});

    readablePcapStream.pipe(parser);

    parser.on('block', (block: any) => {
        blockCounter++;
        if (block.type === 'InterfaceDescriptionBlock') {
            currentInterfaceInfo[block.interfaceId] = { name: block.options?.if_name, linkLayerType: block.linkLayerType, tsresol: block.options?.if_tsresol !== undefined ? Number(block.options.if_tsresol) : 6 };
        }
    });

    parser.on('data', (pcapNgPacket: any) => {
      if (promiseResolved) return;
      dataEventCounter++;
      if (!pcapNgPacket.data) { return; }
      packetCounter++;

      const interfaceId = pcapNgPacket.interfaceId === undefined ? 0 : pcapNgPacket.interfaceId;
      const ifaceInfo = currentInterfaceInfo[interfaceId] || { linkLayerType: 1, tsresol: 6 };
      const timestamp = getTimestamp(null, true, pcapNgPacket, ifaceInfo);
      const packetLength = pcapNgPacket.capturedLength || pcapNgPacket.data.length;
      const packetDataBuffer = pcapNgPacket.data;

      let sourceIp = "N/A", destIp = "N/A", protocol = "UNKNOWN", info = `Len ${packetLength}`;
      let sourcePort: number | undefined, destPort: number | undefined;
      let isError = false, errorType: string | undefined = undefined;
      let flags: string[] = [];
      let payloadHexSample = "";
      let voipDetails: any = null;

      try {
        const linkLayerType = ifaceInfo.linkLayerType;
        let currentOffset = 0;
        if (linkLayerType === 1 && packetDataBuffer && packetDataBuffer.length >=14) {
            const etherType = packetDataBuffer.readUInt16BE(12);
            currentOffset = 14;
            if (etherType === 0x0800) { // IPv4
                protocol = "IPv4";
                if (packetDataBuffer.length >= currentOffset + 20) {
                    const ipHeaderIHL = (packetDataBuffer[currentOffset] & 0x0F);
                    const ipHeaderLength = ipHeaderIHL * 4;
                    if (packetDataBuffer.length >= currentOffset + ipHeaderLength) {
                        const ipHeader = packetDataBuffer.slice(currentOffset, currentOffset + ipHeaderLength);
                        sourceIp = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
                        destIp = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
                        const ipProtocolField = ipHeader[9];
                        info = `IPv4 ${sourceIp} -> ${destIp}`;
                        currentOffset += ipHeaderLength;
                        let transportHeaderStart = currentOffset;

                        if (ipProtocolField === 1) { protocol = "ICMP"; info += ` ICMP`; }
                        else if (ipProtocolField === 6) {
                            protocol = "TCP";
                            if (packetDataBuffer.length >= currentOffset + 20) {
                                sourcePort = packetDataBuffer.readUInt16BE(currentOffset);
                                destPort = packetDataBuffer.readUInt16BE(currentOffset + 2);
                                const flagsByte = packetDataBuffer[currentOffset + 13];
                                const tcpHeaderLength = ((packetDataBuffer[currentOffset+12] & 0xF0) >> 4) * 4;
                                transportHeaderStart = currentOffset + tcpHeaderLength;

                                if (flagsByte & 0x04) { flags.push("RST"); isError = true; errorType = "TCP Reset"; }
                                if (flagsByte & 0x02) flags.push("SYN");
                                if (flagsByte & 0x01) flags.push("FIN");
                                if (flagsByte & 0x10) flags.push("ACK");
                                info = `${sourcePort} → ${destPort} [${flags.join(',')}] TCP`;

                                if (sourcePort === 5060 || destPort === 5060 || sourcePort === 5061 || destPort === 5061) {
                                    protocol = "SIP/TCP";
                                    if (packetDataBuffer.length > transportHeaderStart) payloadHexSample = packetDataBuffer.slice(transportHeaderStart).toString('hex').substring(0, 256);
                                    voipDetails = { signalingProtocol: "SIP", transport: "TCP" };
                                } else if (sourcePort === 2000 || destPort === 2000) {
                                    protocol = "SCCP/TCP";
                                    if (packetDataBuffer.length > transportHeaderStart) payloadHexSample = packetDataBuffer.slice(transportHeaderStart).toString('hex').substring(0, 128);
                                    voipDetails = { signalingProtocol: "SCCP", transport: "TCP" };
                                }
                            } else { isError = true; errorType = "TruncatedTCP_AI_NG"; info += ` TCP (Truncated)`;}
                        }
                        else if (ipProtocolField === 17) {
                            protocol = "UDP";
                            if (packetDataBuffer.length >= currentOffset + 8) {
                                sourcePort = packetDataBuffer.readUInt16BE(currentOffset);
                                destPort = packetDataBuffer.readUInt16BE(currentOffset + 2);
                                transportHeaderStart = currentOffset + 8;
                                info = `${sourcePort} → ${destPort} UDP`;

                                if (sourcePort === 5060 || destPort === 5060) {
                                    protocol = "SIP/UDP";
                                    if (packetDataBuffer.length > transportHeaderStart) payloadHexSample = packetDataBuffer.slice(transportHeaderStart).toString('hex').substring(0, 256);
                                    voipDetails = { signalingProtocol: "SIP", transport: "UDP" };
                                } else if ((sourcePort >= 16384 && sourcePort <= 32767 && sourcePort % 2 === 0) || (destPort >= 16384 && destPort <= 32767 && destPort % 2 === 0) ) {
                                    protocol = "RTP/UDP";
                                    // RTP header is typically 12 bytes
                                    if (packetDataBuffer.length > transportHeaderStart + 12) payloadHexSample = packetDataBuffer.slice(transportHeaderStart + 12).toString('hex').substring(0, 48);
                                    voipDetails = { mediaProtocol: "RTP", transport: "UDP" };
                                } else if ((sourcePort >= 16384 && sourcePort <= 32767 && sourcePort % 2 !== 0) || (destPort >= 16384 && destPort <= 32767 && destPort % 2 !== 0) ) {
                                    protocol = "RTCP/UDP";
                                    if (packetDataBuffer.length > transportHeaderStart) payloadHexSample = packetDataBuffer.slice(transportHeaderStart).toString('hex').substring(0, 64);
                                    voipDetails = { mediaControlProtocol: "RTCP", transport: "UDP" };
                                }
                            } else { isError = true; errorType = "TruncatedUDP_AI_NG"; info += ` UDP (Truncated)`;}
                        }
                        else { protocol = `IPProto ${ipProtocolField}`; }
                    } else { isError = true; errorType = "TruncatedIP_AI_NG"; }
                } else { isError = true; errorType = "ShortIP_AI_NG"; }
            } else if (etherType === 0x86DD) { protocol = "IPv6"; }
            else if (etherType === 0x0806) { protocol = "ARP"; }
            else { protocol = `EtherType_0x${etherType.toString(16)}`; }
        } else { protocol = `LinkType_${linkLayerType}`; }
      } catch (e: any) { info = `Decode Err: ${e.message}`; isError = true; errorType = "DecodingErrorPcapNgAI"; }

      protocolStats[protocol] = (protocolStats[protocol] || 0) + 1;
      if (sourceIp !== "N/A") { if (!ipTraffic[sourceIp]) ipTraffic[sourceIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[sourceIp].sentPackets++; ipTraffic[sourceIp].sentBytes += packetLength; ipTraffic[sourceIp].totalPackets++; ipTraffic[sourceIp].totalBytes += packetLength;}
      if (destIp !== "N/A") { if (!ipTraffic[destIp]) ipTraffic[destIp] = {sentPackets:0,receivedPackets:0,sentBytes:0,receivedBytes:0,totalPackets:0,totalBytes:0}; ipTraffic[destIp].receivedPackets++; ipTraffic[destIp].receivedBytes += packetLength; ipTraffic[destIp].totalPackets++; ipTraffic[destIp].totalBytes += packetLength;}

      if (samplePacketsForAI.length < MAX_SAMPLES_FOR_AI || (isError && samplePacketsForAI.filter(p=>p.isError).length < Math.floor(MAX_SAMPLES_FOR_AI / 2)) ) {
        samplePacketsForAI.push({ no: packetCounter, timestamp, source: sourceIp, destination: destIp, sourcePort, destPort, protocol, length: packetLength, info, isError, errorType, payloadHexSample: payloadHexSample || undefined, voipDetails: voipDetails || undefined });
      }
      if (packetCounter >= MAX_PACKETS_TO_PROCESS_FOR_STATS && samplePacketsForAI.length >= MAX_SAMPLES_FOR_AI) { cleanupAndFinish("resolved", prepareAiData()); }
    });

    const prepareAiData = () => {
        const topProtocols = Object.entries(protocolStats).sort(([,a],[,b]) => b-a).slice(0, 7).reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});
        const calculatedTopTalkers = Object.entries(ipTraffic).map(([ip, data]) => ({ ip, packets: data.totalPackets, bytes: data.totalBytes, sentPackets:data.sentPackets, receivedPackets:data.receivedPackets, sentBytes:data.sentBytes, receivedBytes:data.receivedBytes })).sort((a, b) => b.bytes - a.bytes).slice(0, 7);
        return { statistics: { totalPacketsInFile: packetCounter, packetsProcessedForStats: packetCounter, protocols: topProtocols, topTalkers: calculatedTopTalkers.length > 0 ? calculatedTopTalkers : [{ip: "N/A", packets:0, bytes:0, sentPackets:0, receivedPackets:0, sentBytes:0, receivedBytes:0}], anomalyScore: Math.floor(Math.random() * 30) + 10, }, samplePackets: samplePacketsForAI, };
    };
    parser.on('end', () => { if (!promiseResolved) cleanupAndFinish("resolved", prepareAiData()); });
    parser.on('error', (err: Error) => { if (!promiseResolved) cleanupAndFinish("rejected", new Error(`PCAPNGParser stream error for AI: ${err.message}`)); });
  });
}


const groqApiKey = process.env.GROQ_API_KEY;
const modelNameFromEnv = process.env.GROQ_MODEL_NAME || "llama3-70b-8192";
let groqProvider: ReturnType<typeof createGroq> | null = null;

if (groqApiKey && groqApiKey.trim() !== "") {
  groqProvider = createGroq({ apiKey: groqApiKey });
  console.log("[API_ANALYZE_PCAP_CONFIG] Groq provider configured.");
} else {
  console.error("[CRITICAL_CONFIG_ERROR] GROQ_API_KEY environment variable is missing or empty. AI features will be disabled.");
}

function extractJsonFromString(text: string): string | null {
    if (!text || text.trim() === "") {
        console.warn("[EXTRACT_JSON] AI returned empty or whitespace-only text.");
        return null;
    }
    const markdownRegex = /```(?:json)?\s*([\s\S]*?)\s*```/;
    const markdownMatch = text.match(markdownRegex);

    if (markdownMatch && markdownMatch[1]) {
        const extracted = markdownMatch[1].trim();
        return extracted;
    }
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
        const potentialJson = text.substring(firstBrace, lastBrace + 1);
        try { JSON.parse(potentialJson); return potentialJson; } catch (e) { /* ignore */ }
    }
    return text.trim() === "" ? null : text.trim();
}

export async function POST(request: NextRequest) {
  let analysisIdFromBody: string | undefined;
  let rawAnalysisTextForErrorLog: string | undefined;
  let cleanedJsonTextForErrorLog: string | undefined;

  try {
    const body = await request.json();
    analysisIdFromBody = body.analysisId;
    console.log(`[API_ANALYZE_PCAP_V7_VOIP_FINAL] Received request for analysisId: ${analysisIdFromBody}`);

    if (!groqProvider) {
      return NextResponse.json({ error: "AI Provider (Groq) is not configured." }, { status: 500 });
    }
    if (!analysisIdFromBody) {
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 });
    }

    const pcapRecord = await db.pcapFile.findUnique({ analysisId: analysisIdFromBody });
    if (!pcapRecord || !pcapRecord.blobUrl) {
      return NextResponse.json({ error: "PCAP file metadata or URL not found" }, { status: 404 });
    }

    let extractedPcapData;
    const fileName = pcapRecord.originalName || pcapRecord.fileName || "unknown_file";
    if (fileName.toLowerCase().endsWith(".pcapng")) {
        console.log(`[API_ANALYZE_PCAP_V7_VOIP_FINAL] Using AI_PCAPNG_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapFileForAIWithPcapNgParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    } else {
        console.log(`[API_ANALYZE_PCAP_V7_VOIP_FINAL] Using AI_ORIGINAL_PARSER for ${fileName}`);
        extractedPcapData = await parsePcapForAIWithOriginalParser(pcapRecord.blobUrl, fileName, analysisIdFromBody);
    }

    if (!extractedPcapData || !extractedPcapData.samplePackets) {
        return NextResponse.json({ error: "Failed to parse PCAP file data for AI." }, { status: 500 });
    }

    const errorPacketsForAI = (extractedPcapData.samplePackets || [])
        .filter((packet: any) => packet.isError && packet.errorType)
        .map((packet: any) => ({
            no: packet.no,
            errorType: packet.errorType,
            infoFromParser: packet.info,
            source: packet.source,
            destination: packet.destination,
            sourcePort: packet.sourcePort,
            destPort: packet.destPort,
            protocol: packet.protocol,
            timestamp: packet.timestamp,
            payloadHexSample: packet.payloadHexSample, // Ini sudah ada dari parser
            voipDetails: packet.voipDetails // Ini juga sudah ada dari parser
        })).slice(0, MAX_ERROR_INSTANCES_FOR_AI);

    console.log(`[API_ANALYZE_PCAP_V7_VOIP_FINAL] Error packets for AI (${errorPacketsForAI.length} instances):`, JSON.stringify(errorPacketsForAI.map(p => ({no: p.no, type: p.errorType}))));

    const dataForAI = {
      analysisId: analysisIdFromBody,
      fileName: pcapRecord.originalName,
      fileSize: pcapRecord.size,
      statistics: extractedPcapData.statistics,
      samplePackets: extractedPcapData.samplePackets.slice(0, MAX_SAMPLES_FOR_AI),
      errorPacketsForDetailedAnalysis: errorPacketsForAI,
    };

    const { text: rawAnalysisText } = await generateText({
      model: groqProvider(modelNameFromEnv as any),
      prompt:  `
        You are a network security expert and VoIP specialist analyzing PCAP data.
        File: "${dataForAI.fileName}" (size: ${dataForAI.fileSize} bytes, ID: ${dataForAI.analysisId}).

        Extracted Data:
        - General Statistics: ${JSON.stringify(dataForAI.statistics, null, 2)}
        - General Sample Packets (up to ${MAX_SAMPLES_FOR_AI}, 'no' is packet num. Some may include 'payloadHexSample' and 'voipDetails'): ${JSON.stringify(dataForAI.samplePackets, null, 2)}
        - Specific Error Packets for Detailed Analysis (up to ${MAX_ERROR_INSTANCES_FOR_AI} instances. Some may include 'payloadHexSample' and 'voipDetails'): ${JSON.stringify(dataForAI.errorPacketsForDetailedAnalysis, null, 2)}

        Based on THIS SPECIFIC data:
        1.  Provide a concise overall summary of findings and security posture.
        2.  Determine a threat level (low, medium, high, critical).
        3.  Provide a traffic behavior score (0-100, 0=benign, 100=malicious) with justification.
        4.  **Detailed Error Analysis**: For EACH packet in 'Specific Error Packets for Detailed Analysis' (if any, analyze ALL provided instances):
            - packetNumber: (the 'no' field from the error packet)
            - errorType: (e.g., "TCP Reset", "SIP Error 404", "RTP Out-of-Order")
            - packetInfoFromParser: (the 'infoFromParser' field, which is a brief summary from the parser)
            - detailedExplanation: In-depth explanation of this error in the context of THIS packet (source IP/Port, destination IP/Port, protocol, 'voipDetails' if present, and its parser-generated info). How does 'payloadHexSample' (if present) clarify the error?
            - probableCauseInThisContext: Based on this packet's details and 'payloadHexSample' (if available), what's the most probable cause for this error instance?
            - specificActionableRecommendations: [Array of 1-2 concise, actionable steps for THIS specific error instance.]
        5.  **VoIP Traffic Analysis (If any VoIP protocols like SIP, RTP, RTCP, SCCP, H.323 are present in General Sample Packets, 'voipDetails' in Error Packets, or Statistics, or indicated by port numbers):**
            - voipSummary: Brief summary of VoIP activity. Note if CUCM (Cisco Unified Communications Manager) context is suspected (e.g., SCCP traffic, common CUCM ports, or SIP packets with Cisco user-agents identified from 'payloadHexSample' if present). Describe the overall health of VoIP communication. Are there patterns of successful calls, failed calls, or quality issues based on the samples?
            - detectedCalls: [Array of objects, each representing a call flow identified. Infer from 'voipDetails' like 'callId', 'sipFrom', 'sipTo', 'rtpSsrc' and signaling messages in 'payloadHexSample'. Use timestamps for startTime/endTime.
                {callId (string, from SIP if available), callerIp (string), callerPort (number), calleeIp (string), calleePort (number), protocol (string, e.g., 'SIP', 'SCCP', 'RTP'), startTime (ISO string), endTime (ISO string, optional), duration (string, e.g., "30s", "N/A" if not calculable),
                status (string, e.g., 'Completed', 'Failed - No Answer', 'Failed - Busy', 'Failed - Server Error (SIP 503)', 'Failed - Client Error (SIP 404)', 'Ringing', 'InProgress', 'Error - RTP Missing', 'Unknown'),
                failureReason (string, if status indicates failure, e.g. "SIP/2.0 404 Not Found in payload", "No RTP stream detected after call setup"),
                relatedPacketNumbers (array of numbers, 'no' from samplePackets for this call),
                qualityMetrics (object, optional, e.g., { "jitter": "5ms (avg)", "packetLoss": "0.1%", "mos": "4.1 (estimated)" } - infer from RTCP if possible or state N/A)
                }
              ]
            - potentialVoipIssues: [Array of objects, each for a potential issue:
                {issueType (string, e.g., 'OneWayAudio', 'NoAudio', 'HighJitterIndication', 'PacketLossIndication', 'RegistrationFailure', 'SignalingError', 'CUCMCommunicationProblem', 'CallDropAbruptly', 'CodecMismatchSuspected', 'SIPRequestTimeout'),
                description (string),
                evidence (string, e.g., "Only one-way RTP stream seen for call ID X.", "SIP REGISTER for endpoint Y failed with 401.", "RTCP RR packet #Z indicates high packet loss for SSRC A."),
                recommendation (string), severity (string, 'Low', 'Medium', 'High')}
              ]
            - cucmSpecificAnalysis (Only if CUCM context is strongly suspected, or SCCP protocol is identified): {
                registrationIssues: ["Describe any phone/endpoint registration problems with CUCM, citing specific SCCP messages (e.g. from 'payloadHexSample' or 'voipDetails') or SIP REGISTER failures if seen. Identify involved IPs/MACs if possible."],
                callProcessingErrors: ["Describe any call setup/teardown errors that seem related to CUCM call processing logic. Identify where the problem likely lies (e.g., endpoint-to-CUCM, CUCM-to-gateway, CUCM internal problem). Provide evidence from packet samples or 'voipDetails'."],
                commonCUCMProblemsObserved: "Note any patterns indicative of common CUCM issues like Media Termination Point (MTP) resource problems, gateway misconfiguration, SCCP keepalive failures, or specific CUCM error codes if identifiable from payloads/voipDetails. Explain the implication."
              }
            - If no VoIP traffic or no significant VoIP issues are detected from samples, this entire 'voipAnalysisReport' section in JSON can be an empty object or its sub-arrays can be empty, with a note in 'voipSummary' like "No significant VoIP traffic or issues detected for deep analysis based on the provided packet samples.".
        6.  List up to 5 general security findings. For each:
            - id, title, description, severity, confidence, recommendation, category, affectedHosts (optional), relatedPacketSamples (optional).
        7.  Identify up to 3-5 Indicators of Compromise (IOCs). For each:
            - type, value, context, confidence.
        8.  Suggest 2-3 general recommendations for security improvement. For each:
            - title, description, priority.
        9.  Create a brief timeline of up to 3-5 most significant events. For each:
            - time, event, severity.

        Format your ENTIRE response strictly as a single JSON object.
        {
          "summary": "...",
          "threatLevel": "...",
          "trafficBehaviorScore": { "score": 0, "justification": "..." },
          "detailedErrorAnalysis": [
            {
              "packetNumber": 0,
              "errorType": "ExampleErrorType",
              "packetInfoFromParser": "...",
              "detailedExplanation": "...",
              "probableCauseInThisContext": "...",
              "specificActionableRecommendations": ["...", "..."]
            }
          ],
          "voipAnalysisReport": {
            "voipSummary": "...",
            "detectedCalls": [{ "callId": "example", "callerIp":"1.2.3.4", "callerPort":5060, "calleeIp":"5.6.7.8", "calleePort":5060, "protocol":"SIP", "startTime":"...", "endTime":"...", "duration":"...", "status":"Failed - No Answer", "failureReason":"SIP/2.0 408 Timeout", "relatedPacketNumbers":[], "qualityMetrics": {} }],
            "potentialVoipIssues": [{ "issueType":"SignalingError", "description":"...", "evidence":"...", "recommendation":"...", "severity":"Medium" }],
            "cucmSpecificAnalysis": {
                "registrationIssues": [],
                "callProcessingErrors": [],
                "commonCUCMProblemsObserved": "N/A"
            }
          },
          "findings": [ { "id": "...", "title": "...", "description": "...", "severity": "...", "confidence": 0, "recommendation": "...", "category": "...", "affectedHosts": [], "relatedPacketSamples": [] } ],
          "iocs": [ { "type": "ip", "value": "...", "context": "...", "confidence": 0 } ],
          "statistics": ${JSON.stringify(dataForAI.statistics)},
          "recommendations": [ { "title": "...", "description": "...", "priority": "..." } ],
          "timeline": [ { "time": "...", "event": "...", "severity": "..." } ]
        }
        The entire response MUST be ONLY the JSON object.
      `,
    });

    rawAnalysisTextForErrorLog = rawAnalysisText;
    const cleanedJsonText = extractJsonFromString(rawAnalysisText);
    cleanedJsonTextForErrorLog = cleanedJsonText;

    if (!cleanedJsonText) {
        console.error("[API_ANALYZE_PCAP_V7_VOIP_FINAL] Cleaned JSON text is null or empty. Raw AI response:", rawAnalysisTextForErrorLog);
        throw new Error("AI returned empty or unrecoverable data after cleaning attempts.");
    }

    // === TAMBAHKAN LOG DI SINI ===
    console.log("[API_ANALYZE_PCAP_V7_VOIP_FINAL] Attempting to parse cleaned JSON (first 500 chars):", cleanedJsonText.substring(0, 500) + "...");
    // ============================

    const aiAnalysis = JSON.parse(cleanedJsonText);

    return NextResponse.json({
      success: true,
      analysis: {
        ...aiAnalysis,
        fileName: dataForAI.fileName,
        fileSize: dataForAI.fileSize,
        uploadDate: pcapRecord.createdAt.toISOString(),
        samplePacketsForContext: extractedPcapData.samplePackets,
        statistics: aiAnalysis.statistics || dataForAI.statistics,
      }
    });

  } catch (error) {
    const analysisIdForLogError = analysisIdFromBody || 'unknown';
    console.error(`[API_ANALYZE_PCAP_V7_VOIP_FINAL] Error for analysisId: ${analysisIdForLogError}:`, error);
    const errorMessage = error instanceof Error ? error.message : "Unexpected AI analysis error.";

    if (error instanceof SyntaxError) {
        console.error("[API_ANALYZE_PCAP_V7_VOIP_FINAL] SyntaxError. Cleaned text that failed parsing (first 1KB):", cleanedJsonTextForErrorLog?.substring(0, 1024));
        // @ts-ignore
        const errorPosition = error.at;
        // @ts-ignore
        const errorLine = error.lineNumber;
        // @ts-ignore
        const errorColumn = error.columnNumber;

        let errorContext = "";
        if (cleanedJsonTextForErrorLog && typeof errorPosition === 'number') {
            const start = Math.max(0, errorPosition - 50);
            const end = Math.min(cleanedJsonTextForErrorLog.length, errorPosition + 50);
            errorContext = cleanedJsonTextForErrorLog.substring(start, end);
        }
        console.error(`[API_ANALYZE_PCAP_V7_VOIP_FINAL] JSON SyntaxError context (around pos ${errorPosition}): "...${errorContext}..."`);

        return NextResponse.json({
            error: "Failed to parse AI response. Invalid JSON.",
            details: errorMessage,
            rawTextSample: rawAnalysisTextForErrorLog?.substring(0, 2000),
            cleanedTextSample: cleanedJsonTextForErrorLog?.substring(0,2000),
            errorPositionInfo: { at: errorPosition, line: errorLine, column: errorColumn, contextAroundError: errorContext }
        }, { status: 500 });
    }

    if (error instanceof Error && (error.name === 'AI_LoadAPIKeyError' || error.message.includes("API key") || error.message.includes("authentication"))) {
        return NextResponse.json({ error: "AI Provider API key error.", details: error.message }, { status: 500 });
    }

    return NextResponse.json({ error: errorMessage, details: error instanceof Error ? error.stack : "No stack" }, { status: 500 });
  }
}
