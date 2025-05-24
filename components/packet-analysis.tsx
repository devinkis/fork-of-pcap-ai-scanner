"use client";

import { useState, useEffect, useRef } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Loader2, FileDown, AlertTriangle, X, RefreshCw, FileWarning, FileText } from "lucide-react"; // Tambahkan FileWarning, FileText
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area"; // Impor ScrollArea

interface Packet {
  id: number;
  timestamp: string;
  sourceIp: string;
  sourcePort?: number;
  destIp: string;
  destPort?: number;
  protocol: string;
  length: number;
  info: string;
  flags?: string[];
  tcpSeq?: number;
  tcpAck?: number;
  windowSize?: number;
  ttl?: number;
  isError?: boolean;
  errorType?: string;
  hexDump?: string[];
  detailedInfo?: { // Ini akan diisi oleh backend
    [key: string]: any;
  };
}

interface Connection {
  id: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: string;
  state: string;
  packets: number[]; 
  startTime: string;
  endTime?: string;
  hasErrors: boolean;
  errorTypes: string[];
}

interface BlobFile {
  url: string;
  pathname: string;
  size: number;
  uploadedAt: string;
  metadata?: {
    analysisId?: string;
    originalName?: string;
    size?: string;
    uploadedAt?: string;
  };
}

interface PacketAnalysisProps {
  analysisId: string;
}

export function PacketAnalysis({ analysisId }: PacketAnalysisProps) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [pcapFile, setPcapFile] = useState<BlobFile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [showOnlyErrors, setShowOnlyErrors] = useState(false);
  const [filterType, setFilterType] = useState<string>("all");
  const tableRef = useRef<HTMLDivElement>(null);

  const fetchPcapAndPacketData = async () => {
    setLoading(true);
    setError(null);
    setPackets([]);
    setConnections([]);
    setSelectedPacket(null); // Reset selected packet

    try {
      // 1. Fetch PCAP file info (untuk tombol download)
      const pcapInfoResponse = await fetch(`/api/get-pcap/${analysisId}`);
      if (!pcapInfoResponse.ok) {
        const errorData = await pcapInfoResponse.json().catch(() => ({error: "Failed to fetch PCAP file information"}));
        throw new Error(errorData.error || "Failed to fetch PCAP file information");
      }
      const pcapInfoData = await pcapInfoResponse.json();
      if (pcapInfoData.success && pcapInfoData.files.length > 0) {
        setPcapFile(pcapInfoData.files[0]);
      }

      // 2. Fetch parsed packet data from new API endpoint
      console.log(`[PACKET_ANALYSIS_FE] Fetching parsed packet data for analysisId: ${analysisId}`);
      const packetDataResponse = await fetch(`/api/get-packet-data/${analysisId}`);
      if (!packetDataResponse.ok) {
          const errorData = await packetDataResponse.json().catch(() => ({error: "Failed to fetch packet data from API"}));
          throw new Error(errorData.error || "Failed to fetch packet data from API");
      }
      const parsedData = await packetDataResponse.json();

      if (parsedData.success) {
        console.log(`[PACKET_ANALYSIS_FE] Received ${parsedData.packets?.length || 0} packets and ${parsedData.connections?.length || 0} connections.`);
        setPackets(parsedData.packets || []);
        setConnections(parsedData.connections || []); 
      } else {
        throw new Error(parsedData.error || "API returned non-success for packet data");
      }
    } catch (err) {
      console.error("Error fetching PCAP/packet data:", err);
      setError(err instanceof Error ? err.message : "An unknown error occurred");
      setPackets([]); 
      setConnections([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (analysisId) {
      fetchPcapAndPacketData();
    }
  }, [analysisId]);
  
  const filteredPackets = packets.filter((packet) => {
    const filterText = filter.toLowerCase();
    const textMatch =
      filter === "" ||
      packet.id.toString().includes(filterText) ||
      packet.timestamp.toLowerCase().includes(filterText) ||
      packet.sourceIp?.toLowerCase().includes(filterText) ||
      (packet.sourcePort?.toString().includes(filterText)) ||
      packet.destIp?.toLowerCase().includes(filterText) ||
      (packet.destPort?.toString().includes(filterText)) ||
      packet.protocol?.toLowerCase().includes(filterText) ||
      packet.length?.toString().includes(filterText) ||
      packet.info?.toLowerCase().includes(filterText);

    const errorMatch = !showOnlyErrors || packet.isError;

    let typeMatch = true;
    if (filterType === "tcp-reset") {
      typeMatch = packet.errorType === "TCP Reset" || packet.errorType === "TCP Reset from Client";
    } else if (filterType === "failed-handshake") {
      typeMatch = packet.errorType === "Failed Handshake";
    } else if (filterType === "connection-issues") {
      typeMatch = packet.isError === true && !!packet.errorType;
    } else if (filterType !== "all" && packet.protocol) { 
        typeMatch = packet.protocol.toUpperCase().includes(filterType.toUpperCase());
    }
    return textMatch && errorMatch && typeMatch;
  });

  const getProtocolColor = (protocol?: string) => { 
    if (!protocol) return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
    const upperProto = protocol.toUpperCase();
    if (upperProto.includes("TCP")) return "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300";
    if (upperProto.includes("UDP")) return "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300";
    if (upperProto.includes("HTTP")) return "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-300";
    if (upperProto.includes("HTTPS")) return "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/50 dark:text-indigo-300";
    if (upperProto.includes("DNS")) return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300";
    if (upperProto.includes("ICMP")) return "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300";
    if (upperProto.includes("ARP")) return "bg-pink-100 text-pink-800 dark:bg-pink-900/50 dark:text-pink-300";
    if (upperProto.includes("IPV4")) return "bg-teal-100 text-teal-800 dark:bg-teal-900/50 dark:text-teal-300";
    if (upperProto.includes("IPV6")) return "bg-cyan-100 text-cyan-800 dark:bg-cyan-900/50 dark:text-cyan-300";
    return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
  };

  const getRowClassName = (packet: Packet) => {
    if (packet.isError) return "bg-red-50 dark:bg-red-900/20";
    return "";
  };

  const downloadPcapFile = async () => {
    if (!pcapFile) return;
    try {
      const response = await fetch(pcapFile.url);
      if (!response.ok) throw new Error("Failed to download file");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = pcapFile.metadata?.originalName || "download.pcap";
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (downloadError) {
      console.error("Error downloading file:", downloadError);
      setError("Failed to download PCAP file");
    }
  };

  const handlePacketClick = (packet: Packet) => {
    setSelectedPacket(packet);
    if (tableRef.current) {
      const row = tableRef.current.querySelector(`tr[data-packet-id="${packet.id}"]`);
      if (row) {
        row.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    }
  };
  
  const applyFilter = (type: string) => { setFilterType(type); };

  if (error && !loading) { 
    return (
      <Card>
        <CardHeader><CardTitle className="text-red-500">Error Loading Packet Data</CardTitle></CardHeader>
        <CardContent>
          <p>{error}</p>
          <Button onClick={fetchPcapAndPacketData} className="mt-4"> Try Again </Button>
        </CardContent>
      </Card>
    );
  }

  if (loading && packets.length === 0) {
     return (
      <div className="space-y-4">
        <div className="flex justify-between items-center">
            <h2 className="text-xl font-semibold">Packet Analysis</h2>
        </div>
        <Card>
            <CardHeader className="pb-2"><CardTitle>Packet Summary</CardTitle></CardHeader>
            <CardContent className="flex justify-center items-center h-60">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                <p className="ml-2">Loading packet data...</p>
            </CardContent>
        </Card>
      </div>
     );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
        <h2 className="text-xl font-semibold">Packet Analysis</h2>
        <div className="flex gap-2 items-center">
          {pcapFile && (
            <Button variant="outline" size="sm" onClick={downloadPcapFile}>
              <FileDown className="h-4 w-4 mr-2" />
              Download PCAP
            </Button>
          )}
           <Button variant="outline" size="sm" onClick={fetchPcapAndPacketData} disabled={loading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
        </div>
      </div>

      {pcapFile?.metadata && (
        <div className="text-sm text-muted-foreground">
          Analyzing file: {pcapFile.metadata.originalName || "Unknown file"} (
          {pcapFile.metadata.size ? (Number.parseInt(pcapFile.metadata.size) / (1024 * 1024)).toFixed(2) : "?"} MB)
        </div>
      )}

      <div className="flex flex-col gap-4">
        <div className="flex flex-col sm:flex-row flex-wrap gap-2 items-center">
          <div className="flex items-center gap-2">
            <Input
              placeholder="Filter packets (ID, IP, Port, Proto, Info...)"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-full sm:w-64"
            />
            <Button variant="ghost" size="icon" onClick={() => setFilter("")} disabled={!filter} className="h-9 w-9">
              <X className="h-4 w-4" />
            </Button>
          </div>

          <Select value={filterType} onValueChange={applyFilter}>
            <SelectTrigger className="w-full sm:w-[180px]"> <SelectValue placeholder="Filter type" /> </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Packets</SelectItem>
              <SelectItem value="TCP">TCP Only</SelectItem>
              <SelectItem value="UDP">UDP Only</SelectItem>
              <SelectItem value="ICMP">ICMP Only</SelectItem>
              <SelectItem value="ARP">ARP Only</SelectItem>
              <SelectItem value="IPv4">IPv4 Only</SelectItem>
              <SelectItem value="IPv6">IPv6 Only</SelectItem>
              <SelectItem value="tcp-reset">TCP Resets</SelectItem>
              <SelectItem value="failed-handshake">Failed Handshakes</SelectItem>
              <SelectItem value="connection-issues">Other Errors</SelectItem>
            </SelectContent>
          </Select>

          <div className="flex items-center gap-2 pt-2 sm:pt-0">
            <Checkbox id="show-errors" checked={showOnlyErrors} onCheckedChange={(checked) => setShowOnlyErrors(checked as boolean)} />
            <label htmlFor="show-errors" className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
              Show only errors
            </label>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Packet List</CardTitle>
                <CardDescription>
                  Showing {filteredPackets.length} of {packets.length} packets.
                  {showOnlyErrors && packets.filter((p) => p.isError).length > 0 && 
                    ` (${packets.filter((p) => p.isError).length} errors found)`}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {loading && packets.length === 0 ? ( 
                  <div className="flex justify-center items-center h-60">
                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                  </div>
                ) : packets.length === 0 && !loading ? (
                    <div className="text-center py-10 text-muted-foreground">
                        <FileWarning className="h-10 w-10 mx-auto mb-2"/>
                        No packets found or parsed for this file.
                    </div>
                ): (
                  <ScrollArea className="rounded-md border overflow-x-auto max-h-[calc(100vh-25rem)] min-h-[200px]" ref={tableRef}>
                    <Table>
                      <TableHeader className="sticky top-0 bg-background z-10 shadow-sm dark:bg-slate-900">
                        <TableRow>
                          <TableHead className="w-12">No.</TableHead>
                          <TableHead>Time</TableHead>
                          <TableHead>Source</TableHead>
                          <TableHead>Destination</TableHead>
                          <TableHead>Protocol</TableHead>
                          <TableHead>Length</TableHead>
                          <TableHead>Info</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredPackets.map((packet) => (
                          <TableRow
                            key={packet.id}
                            className={`${getRowClassName(packet)} ${
                              selectedPacket?.id === packet.id ? "bg-muted dark:bg-slate-700" : ""
                            } cursor-pointer hover:bg-muted/50 dark:hover:bg-slate-700/50`}
                            onClick={() => handlePacketClick(packet)}
                            data-packet-id={packet.id}
                          >
                            <TableCell className="font-medium text-xs">
                              {packet.isError && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                              {packet.id}
                            </TableCell>
                            <TableCell className="text-xs">{new Date(packet.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}</TableCell>
                            <TableCell className="text-xs font-mono">{packet.sourceIp}{packet.sourcePort ? `:${packet.sourcePort}` : ''}</TableCell>
                            <TableCell className="text-xs font-mono">{packet.destIp}{packet.destPort ? `:${packet.destPort}` : ''}</TableCell>
                            <TableCell><Badge variant="outline" className={`${getProtocolColor(packet.protocol)} text-xs px-1.5 py-0.5`}>{packet.protocol}</Badge></TableCell>
                            <TableCell className="text-xs">{packet.length} B</TableCell>
                            <TableCell className={`max-w-xs truncate text-xs ${packet.isError ? "text-red-600 font-medium" : ""}`}>
                              {packet.info}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                    {filteredPackets.length === 0 && !loading && packets.length > 0 && (
                         <div className="text-center py-10 text-muted-foreground">No packets match your current filters.</div>
                    )}
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="sticky top-6"> 
            {selectedPacket ? (
              <Card className="max-h-[calc(100vh-5rem)]"> 
                <CardHeader className="pb-2">
                  <CardTitle className="flex justify-between items-center text-lg">
                    <span>Packet #{selectedPacket.id} Details</span>
                    <Button variant="ghost" size="icon" onClick={() => setSelectedPacket(null)} className="h-7 w-7"><X className="h-4 w-4"/></Button>
                  </CardTitle>
                </CardHeader>
                <ScrollArea className="max-h-[calc(100vh-10rem)]"> 
                    <CardContent className="p-0">
                    <Tabs defaultValue="details">
                        <TabsList className="w-full justify-start rounded-none border-b bg-transparent p-0 dark:border-gray-700">
                        <TabsTrigger value="details" className="rounded-none border-b-2 border-transparent px-4 py-2 data-[state=active]:border-primary data-[state=active]:text-primary">Details</TabsTrigger>
                        <TabsTrigger value="hex" className="rounded-none border-b-2 border-transparent px-4 py-2 data-[state=active]:border-primary data-[state=active]:text-primary">Hex View</TabsTrigger>
                        </TabsList>
                        <TabsContent value="details" className="p-4 text-sm">
                        <Accordion type="multiple" defaultValue={["Frame Information", "IPv4", "TCP", "UDP", "ICMP"]}>
                            {selectedPacket.detailedInfo && Object.entries(selectedPacket.detailedInfo).map(([section, details], index) => (
                                <AccordionItem key={index} value={section}>
                                    <AccordionTrigger>{section}</AccordionTrigger>
                                    <AccordionContent className="space-y-1 text-xs">
                                    {typeof details === 'object' && details !== null ? Object.entries(details).map(([key, value], i) => (
                                        <div key={i} className="grid grid-cols-[minmax(100px,auto)_1fr] gap-x-2"> {/* Lebar kolom kunci disesuaikan */}
                                            <div className="font-semibold break-words text-muted-foreground">{key}:</div>
                                            <div className="break-words font-mono">{String(value)}</div>
                                        </div>
                                    )) : <div className="break-words font-mono">{String(details)}</div>}
                                    </AccordionContent>
                                </AccordionItem>
                            ))}
                        </Accordion>

                        {selectedPacket.isError && selectedPacket.errorType && (
                            <Alert variant="destructive" className="mt-4">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertTitle>Error: {selectedPacket.errorType}</AlertTitle>
                            <AlertDescription>
                                An error was detected for this packet.
                            </AlertDescription>
                            </Alert>
                        )}
                        </TabsContent>
                        <TabsContent value="hex" className="p-4">
                        <ScrollArea className="h-[200px] w-full rounded-md border p-2 bg-muted/30 dark:bg-slate-800">
                            <pre className="font-mono text-xs whitespace-pre-wrap break-all overflow-x-auto"> {/* pre-wrap dan break-all */}
                                {selectedPacket.hexDump && selectedPacket.hexDump.length > 0 
                                ? selectedPacket.hexDump.join('\n') 
                                : "Hex dump not available."}
                            </pre>
                        </ScrollArea>
                        </TabsContent>
                    </Tabs>
                    </CardContent>
                </ScrollArea>
              </Card>
            ) : (
              <Card>
                <CardHeader><CardTitle className="text-lg">Packet Details</CardTitle></CardHeader>
                <CardContent className="text-center py-8 text-muted-foreground">
                  <FileText className="h-10 w-10 mx-auto mb-2"/>
                  <p>Select a packet from the list to view its details.</p>
                </CardContent>
              </Card>
            )}

            <Card className="mt-4">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Connection Summary</CardTitle>
                <CardDescription>
                  {connections.length} connections detected
                  {connections.filter((c) => c.hasErrors).length > 0 && 
                    ` (${connections.filter((c) => c.hasErrors).length} with errors)`}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {connections.length === 0 && !loading ? (
                     <div className="text-center py-10 text-muted-foreground">No connection data parsed.</div>
                ) : (
                <ScrollArea className="rounded-md border max-h-[200px]">
                  <Table>
                    <TableHeader className="sticky top-0 bg-background z-10 shadow-sm dark:bg-slate-900">
                      <TableRow>
                        <TableHead className="text-xs">Connection</TableHead>
                        <TableHead className="text-xs">Protocol</TableHead>
                        <TableHead className="text-xs">State</TableHead>
                        <TableHead className="text-xs">Packets</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {connections.map((conn) => (
                        <TableRow key={conn.id} className={`${conn.hasErrors ? "bg-red-50 dark:bg-red-900/30" : ""} cursor-pointer hover:bg-muted/50 dark:hover:bg-slate-700/50`}>
                          <TableCell className="font-mono text-xs max-w-xs truncate">
                            {conn.hasErrors && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                            {`${conn.sourceIp}:${conn.sourcePort} → ${conn.destIp}:${conn.destPort}`}
                          </TableCell>
                          <TableCell><Badge variant="outline" className={`${getProtocolColor(conn.protocol)} text-xs px-1.5 py-0.5`}>{conn.protocol}</Badge></TableCell>
                          <TableCell className={`text-xs ${conn.state === "RESET" || conn.state === "CLOSED" || conn.state === "FIN_WAIT" || conn.state === "FIN_ACK" ? "text-orange-600 dark:text-orange-400" : ""}`}>
                            {conn.state}
                          </TableCell>
                          <TableCell className="text-xs">{conn.packets.length}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
