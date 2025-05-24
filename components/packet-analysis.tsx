"use client";

import { useState, useEffect, useRef } from "react";
import { 
    Table, TableBody, TableCell, TableHead, 
    TableHeader, TableRow 
} from "@/components/ui/table";
import { 
    Card, CardContent, CardDescription, 
    CardHeader, CardTitle 
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { 
    Tabs, TabsContent, TabsList, TabsTrigger 
} from "@/components/ui/tabs";
import { 
    Accordion, AccordionContent, AccordionItem, AccordionTrigger 
} from "@/components/ui/accordion";
import { 
    Select, SelectContent, SelectItem, 
    SelectTrigger, SelectValue 
} from "@/components/ui/select";
import { 
    Loader2, FileDown, AlertTriangle, X, RefreshCw, 
    FileWarning, FileText, ListFilter 
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area"; // Pastikan ini diimpor

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
  detailedInfo?: {
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
  const tableContainerRef = useRef<HTMLDivElement>(null); // Ref untuk scroll ke paket terpilih

  const fetchPcapAndPacketData = async () => {
    setLoading(true);
    setError(null);
    setPackets([]);
    setConnections([]);
    setSelectedPacket(null);

    try {
      const pcapInfoResponse = await fetch(`/api/get-pcap/${analysisId}`);
      if (!pcapInfoResponse.ok) {
        const errorData = await pcapInfoResponse.json().catch(() => ({error: "Failed to fetch PCAP file information"}));
        throw new Error(errorData.error || "Failed to fetch PCAP file information");
      }
      const pcapInfoData = await pcapInfoResponse.json();
      if (pcapInfoData.success && pcapInfoData.files.length > 0) {
        setPcapFile(pcapInfoData.files[0]);
      }

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
    if (packet.isError) return "bg-red-50 dark:bg-red-900/30 hover:bg-red-100/70 dark:hover:bg-red-800/40";
    if (selectedPacket?.id === packet.id) return "bg-primary/10 dark:bg-primary/20";
    return "hover:bg-muted/50 dark:hover:bg-muted/20";
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
    // Scroll to the selected packet in the table (opsional, bisa mengganggu jika tabel panjang)
    // if (tableContainerRef.current) {
    //   const row = tableContainerRef.current.querySelector(`[data-packet-id="${packet.id}"]`);
    //   if (row) {
    //     row.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
    //   }
    // }
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
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 mb-4">
            <h2 className="text-2xl font-semibold tracking-tight">Packet Analysis</h2>
            <Skeleton className="h-9 w-24" /> 
        </div>
        <Card>
            <CardHeader className="pb-2"><CardTitle>Packet List</CardTitle><CardDescription><Skeleton className="h-4 w-48"/></CardDescription></CardHeader>
            <CardContent className="flex justify-center items-center h-80"> {/* Lebih tinggi */}
                <Loader2 className="h-10 w-10 animate-spin text-primary" />
                <p className="ml-3 text-muted-foreground">Loading packet data, please wait...</p>
            </CardContent>
        </Card>
      </div>
     );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-4">
        <div>
            <h2 className="text-2xl font-semibold tracking-tight">Packet Analysis</h2>
            {pcapFile?.metadata && (
            <p className="text-sm text-muted-foreground">
                File: {pcapFile.metadata.originalName || "Unknown file"} (
                {pcapFile.metadata.size ? (Number.parseInt(pcapFile.metadata.size) / (1024 * 1024)).toFixed(2) : "?"} MB)
            </p>
            )}
        </div>
        <div className="flex gap-2 items-center flex-wrap sm:flex-nowrap">
          {pcapFile && (
            <Button variant="outline" size="sm" onClick={downloadPcapFile} className="w-full sm:w-auto">
              <FileDown className="h-4 w-4 mr-2" />
              Download PCAP
            </Button>
          )}
           <Button variant="outline" size="sm" onClick={fetchPcapAndPacketData} disabled={loading} className="w-full sm:w-auto">
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
        </div>
      </div>

      <Card className="shadow-md">
        <CardHeader className="border-b dark:border-gray-700">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div className="flex items-center gap-2 flex-grow">
                    <ListFilter className="h-5 w-5 text-muted-foreground"/>
                    <Input
                    placeholder="Filter packets (ID, IP, Port, Proto, Info...)"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    className="h-9 max-w-xs flex-grow"
                    />
                    {filter && (
                        <Button variant="ghost" size="icon" onClick={() => setFilter("")} className="h-9 w-9">
                        <X className="h-4 w-4" />
                        </Button>
                    )}
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                    <Select value={filterType} onValueChange={applyFilter}>
                        <SelectTrigger className="h-9 w-full sm:w-[180px]"> <SelectValue placeholder="Filter by type" /> </SelectTrigger>
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
                        <label htmlFor="show-errors" className="text-sm font-medium leading-none whitespace-nowrap">Show only errors</label>
                    </div>
                </div>
            </div>
        </CardHeader>
        <CardContent className="p-0"> {/* Hapus padding default agar ScrollArea bisa full width */}
            <ScrollArea className="h-[calc(100vh-28rem)] md:h-[500px]" ref={tableContainerRef}> {/* TINGGI SCROLL DIPERBAIKI */}
                <Table className="min-w-full"> {/* Tambah min-w-full untuk tabel horizontal scroll jika perlu */}
                    <TableHeader className="sticky top-0 z-10 bg-background shadow-sm dark:bg-slate-900">
                    <TableRow>
                        <TableHead className="w-16 px-2 py-2 text-xs">No.</TableHead>
                        <TableHead className="px-2 py-2 text-xs">Time</TableHead>
                        <TableHead className="px-2 py-2 text-xs">Source</TableHead>
                        <TableHead className="px-2 py-2 text-xs">Destination</TableHead>
                        <TableHead className="px-2 py-2 text-xs">Protocol</TableHead>
                        <TableHead className="w-20 px-2 py-2 text-xs">Length</TableHead>
                        <TableHead className="px-2 py-2 text-xs min-w-[250px]">Info</TableHead>
                    </TableRow>
                    </TableHeader>
                    <TableBody>
                    {filteredPackets.length > 0 ? (
                        filteredPackets.map((packet) => (
                        <TableRow
                            key={packet.id}
                            className={`${getRowClassName(packet)} cursor-pointer`}
                            onClick={() => handlePacketClick(packet)}
                            data-packet-id={packet.id}
                        >
                            <TableCell className="font-medium text-xs px-2 py-1.5">
                            {packet.isError && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                            {packet.id}
                            </TableCell>
                            <TableCell className="text-xs px-2 py-1.5">{new Date(packet.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}</TableCell>
                            <TableCell className="text-xs font-mono px-2 py-1.5">{packet.sourceIp}{packet.sourcePort ? `:${packet.sourcePort}` : ''}</TableCell>
                            <TableCell className="text-xs font-mono px-2 py-1.5">{packet.destIp}{packet.destPort ? `:${packet.destPort}` : ''}</TableCell>
                            <TableCell className="px-2 py-1.5"><Badge variant="outline" className={`${getProtocolColor(packet.protocol)} text-xs px-1.5 py-0.5 border`}>{packet.protocol}</Badge></TableCell>
                            <TableCell className="text-xs px-2 py-1.5">{packet.length} B</TableCell>
                            <TableCell className={`max-w-sm truncate text-xs px-2 py-1.5 ${packet.isError ? "text-red-600 dark:text-red-400 font-medium" : ""}`}>
                            {packet.info}
                            </TableCell>
                        </TableRow>
                        ))
                    ) : (
                        <TableRow>
                            <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                                {packets.length === 0 && !loading ? "No packets found in this file." : "No packets match your current filters."}
                            </TableCell>
                        </TableRow>
                    )}
                    </TableBody>
                </Table>
            </ScrollArea>
            <CardFooter className="text-xs text-muted-foreground p-2 border-t dark:border-gray-700">
                Showing {filteredPackets.length} of {packets.length} packets.
                {showOnlyErrors && packets.filter((p) => p.isError).length > 0 && 
                ` (${packets.filter((p) => p.isError).length} errors found)`}
            </CardFooter>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mt-6">
        <div className="lg:col-span-3"> {/* Detail Paket */}
            {selectedPacket ? (
            <Card className="shadow-md sticky top-6 max-h-[calc(100vh-8rem)]"> 
                <CardHeader className="pb-2 border-b dark:border-gray-700">
                <div className="flex justify-between items-center">
                    <CardTitle className="text-lg">Packet #{selectedPacket.id} Details</CardTitle>
                    <Button variant="ghost" size="icon" onClick={() => setSelectedPacket(null)} className="h-7 w-7">
                        <X className="h-4 w-4"/>
                    </Button>
                </div>
                <CardDescription className="text-xs">Timestamp: {new Date(selectedPacket.timestamp).toLocaleString()}</CardDescription>
                </CardHeader>
                <ScrollArea className="max-h-[calc(100vh-15rem)]">
                    <CardContent className="p-0">
                        <Tabs defaultValue="details" className="w-full">
                            <TabsList className="grid w-full grid-cols-2 rounded-none">
                                <TabsTrigger value="details" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Details</TabsTrigger>
                                <TabsTrigger value="hex" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Hex View</TabsTrigger>
                            </TabsList>
                            <div className="p-4"> {/* Padding untuk konten Tabs */}
                                <TabsContent value="details" className="mt-0 text-sm space-y-2">
                                    <Accordion type="multiple" defaultValue={["Frame Info", "IPv4", "TCP", "UDP", "ICMP"]} className="w-full">
                                        {selectedPacket.detailedInfo && Object.entries(selectedPacket.detailedInfo).map(([section, detailsObj], index) => (
                                            Object.keys(detailsObj || {}).length > 0 && ( // Hanya render jika detailsObj punya isi
                                            <AccordionItem key={section + index} value={section}>
                                                <AccordionTrigger className="text-sm font-medium">{section}</AccordionTrigger>
                                                <AccordionContent className="space-y-1 text-xs pl-2">
                                                {typeof detailsObj === 'object' && detailsObj !== null ? Object.entries(detailsObj).map(([key, value]) => (
                                                    <div key={key} className="grid grid-cols-[150px_1fr] gap-x-2 items-baseline">
                                                        <div className="font-semibold text-muted-foreground truncate" title={key}>{key}:</div>
                                                        <div className="font-mono break-all">{String(value)}</div>
                                                    </div>
                                                )) : <div className="font-mono break-all">{String(detailsObj)}</div>}
                                                </AccordionContent>
                                            </AccordionItem>
                                            )
                                        ))}
                                    </Accordion>
                                    {selectedPacket.isError && selectedPacket.errorType && (
                                        <Alert variant="destructive" className="mt-4">
                                        <AlertTriangle className="h-4 w-4" />
                                        <AlertTitle>Error: {selectedPacket.errorType}</AlertTitle>
                                        <AlertDescription>An error or anomaly was detected for this packet.</AlertDescription>
                                        </Alert>
                                    )}
                                </TabsContent>
                                <TabsContent value="hex" className="mt-0">
                                    <ScrollArea className="h-[300px] w-full rounded-md border p-3 bg-muted/30 dark:bg-slate-800">
                                        <pre className="font-mono text-xs whitespace-pre-wrap break-all">
                                            {(selectedPacket.hexDump && selectedPacket.hexDump.length > 0) 
                                            ? selectedPacket.hexDump.join('\n') 
                                            : "Hex dump not available or packet data was empty."}
                                        </pre>
                                    </ScrollArea>
                                </TabsContent>
                            </div>
                        </Tabs>
                    </CardContent>
                </ScrollArea>
            </Card>
            ) : (
            <Card className="shadow-md sticky top-6">
                <CardHeader>
                    <CardTitle className="text-lg flex items-center"><FileText className="mr-2 h-5 w-5 text-muted-foreground"/>Packet Details</CardTitle>
                </CardHeader>
                <CardContent className="text-center py-16 text-muted-foreground">
                    <Info className="h-10 w-10 mx-auto mb-3 text-gray-400" />
                    <p>Select a packet from the list to view its details.</p>
                </CardContent>
            </Card>
            )}
        </div> {/* Akhir lg:col-span-3 untuk Detail Paket */}

        <div className="lg:col-span-2"> {/* Connection Summary */}
            <Card className="shadow-md">
                <CardHeader className="pb-2">
                <CardTitle className="text-lg">Connection Summary</CardTitle>
                <CardDescription>
                    {connections.length} connections detected
                    {connections.filter((c) => c.hasErrors).length > 0 && 
                    ` (${connections.filter((c) => c.hasErrors).length} with errors)`}
                </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                    <ScrollArea className="max-h-[calc(100vh-8rem)] md:max-h-[500px]"> {/* Sesuaikan tinggi scroll */}
                        <Table>
                        <TableHeader className="sticky top-0 bg-background z-10 shadow-sm dark:bg-slate-900">
                            <TableRow>
                            <TableHead className="text-xs px-2 py-2">Connection</TableHead>
                            <TableHead className="text-xs px-2 py-2">Protocol</TableHead>
                            <TableHead className="text-xs px-2 py-2">State</TableHead>
                            <TableHead className="text-xs px-2 py-2 w-20">Packets</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {connections.length > 0 ? (
                            connections.map((conn) => (
                            <TableRow key={conn.id} className={`${conn.hasErrors ? "bg-red-50 dark:bg-red-900/30 hover:bg-red-100/70 dark:hover:bg-red-800/40" : "hover:bg-muted/50 dark:hover:bg-muted/20"}`}>
                                <TableCell className="font-mono text-xs max-w-[200px] sm:max-w-xs truncate px-2 py-1.5">
                                {conn.hasErrors && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                                {`${conn.sourceIp}:${conn.sourcePort} → ${conn.destIp}:${conn.destPort}`}
                                </TableCell>
                                <TableCell className="px-2 py-1.5"><Badge variant="outline" className={`${getProtocolColor(conn.protocol)} text-xs px-1.5 py-0.5 border`}>{conn.protocol}</Badge></TableCell>
                                <TableCell className={`text-xs px-2 py-1.5 ${conn.state === "RESET" || conn.state === "CLOSED" || conn.state === "FIN_WAIT" || conn.state === "FIN_ACK" ? "text-orange-600 dark:text-orange-400" : ""}`}>
                                {conn.state}
                                </TableCell>
                                <TableCell className="text-xs px-2 py-1.5">{conn.packets.length}</TableCell>
                            </TableRow>
                            ))
                            ) : (
                                <TableRow>
                                    <TableCell colSpan={4} className="h-24 text-center text-muted-foreground">
                                        {loading ? "Loading connections..." : "No connection data available."}
                                    </TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                        </Table>
                    </ScrollArea>
                </CardContent>
            </Card>
        </div> {/* Akhir lg:col-span-2 untuk Connection Summary */}
      </div>
    </div>
  );
}
