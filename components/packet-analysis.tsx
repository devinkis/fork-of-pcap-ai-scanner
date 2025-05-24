"use client";

import { useState, useEffect, useRef } from "react";
import { 
    Table, TableBody, TableCell, TableHead, 
    TableHeader, TableRow 
} from "@/components/ui/table";
import { 
    Card, CardContent, CardDescription, 
    CardHeader, CardTitle, CardFooter
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
    FileWarning, FileText, ListFilter, Info // Tambahkan Info
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton"; // <-- PASTIKAN IMPOR INI ADA

// Interface (Packet, Connection, BlobFile, PacketAnalysisProps) tetap sama
// dari versi sebelumnya yang sudah Anda miliki dan saya berikan.
// Untuk keringkasan, saya tidak menyertakannya lagi di sini,
// tapi pastikan interface tersebut ada di atas kode komponen ini.

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
    size?: string; // Sebaiknya number, tapi string dari API Blob
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
  const tableContainerRef = useRef<HTMLDivElement>(null);

  const fetchPcapAndPacketData = async () => {
    setLoading(true);
    setError(null);
    setPackets([]); // Kosongkan data lama
    setConnections([]); // Kosongkan data lama
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
      } else if (!pcapInfoData.success) {
        console.warn("API /api/get-pcap did not return success:", pcapInfoData.error);
        // Tidak melempar error di sini agar pengambilan data paket tetap berjalan
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
      setError(err instanceof Error ? err.message : "An unknown error occurred during data fetching");
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
    if (filterType === "tcp-reset" && packet.protocol?.toUpperCase().includes("TCP")) {
      typeMatch = packet.flags?.includes("RST") || packet.errorType === "TCP Reset" || packet.errorType === "TCP Reset from Client";
    } else if (filterType === "failed-handshake" && packet.protocol?.toUpperCase().includes("TCP")) {
      typeMatch = packet.errorType === "Failed Handshake"; // Ini perlu logika deteksi error yang lebih baik di backend
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
    if (upperProto.includes("HTTPS") || upperProto.includes("TLS")) return "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/50 dark:text-indigo-300";
    if (upperProto.includes("DNS")) return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300";
    if (upperProto.includes("ICMP")) return "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300";
    if (upperProto.includes("ARP")) return "bg-pink-100 text-pink-800 dark:bg-pink-900/50 dark:text-pink-300";
    if (upperProto.includes("IPV4")) return "bg-teal-100 text-teal-800 dark:bg-teal-900/50 dark:text-teal-300";
    if (upperProto.includes("IPV6")) return "bg-cyan-100 text-cyan-800 dark:bg-cyan-900/50 dark:text-cyan-300";
    return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
  };

  const getRowClassName = (packet: Packet) => {
    if (packet.isError) return "bg-red-50 dark:bg-red-900/30 hover:bg-red-100/70 dark:hover:bg-red-800/40";
    if (selectedPacket?.id === packet.id) return "bg-primary/10 dark:bg-primary/20"; // Lebih soft untuk highlight
    return "hover:bg-muted/50 dark:hover:bg-muted/30"; // Dark mode hover
  };

  const downloadPcapFile = async () => {
    if (!pcapFile || !pcapFile.url) {
        setError("PCAP file URL not available for download.");
        return;
    }
    try {
      const response = await fetch(pcapFile.url);
      if (!response.ok) throw new Error(`Failed to download file: ${response.statusText}`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = pcapFile.metadata?.originalName || "analysis_download.pcap";
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (downloadError) {
      console.error("Error downloading file:", downloadError);
      setError(downloadError instanceof Error ? downloadError.message : "Failed to download PCAP file");
    }
  };

  const handlePacketClick = (packet: Packet) => {
    setSelectedPacket(packet);
  };
  
  const applyFilter = (type: string) => { setFilterType(type); };

  // Tampilan loading utama saat data pertama kali diambil atau saat refresh
  if (loading && packets.length === 0) {
     return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 mb-4">
            <h2 className="text-2xl font-semibold tracking-tight">Packet Analysis</h2>
            <div className="flex gap-2 items-center">
                <Skeleton className="h-9 w-36" /> {/* Skeleton untuk tombol download */}
                <Skeleton className="h-9 w-24" /> {/* Skeleton untuk tombol refresh */}
            </div>
        </div>
        <Skeleton className="h-5 w-3/4 mb-4" /> {/* Skeleton untuk info file */}
        
        <Card className="shadow-md">
            <CardHeader className="border-b dark:border-gray-700">
                <Skeleton className="h-9 w-full" /> {/* Skeleton untuk filter bar */}
            </CardHeader>
            <CardContent className="p-0">
                <ScrollArea className="h-[calc(100vh-28rem)] md:h-[500px]">
                     <div className="p-4 space-y-2"> {/* Wrapper untuk skeleton rows */}
                        {[...Array(10)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
                     </div>
                </ScrollArea>
            </CardContent>
            <CardFooter className="p-2 border-t dark:border-gray-700">
                <Skeleton className="h-4 w-48"/>
            </CardFooter>
        </Card>
      </div>
     );
  }

  // Tampilan error jika fetch gagal
  if (error && !loading) { 
    return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 mb-4">
            <h2 className="text-2xl font-semibold tracking-tight">Packet Analysis</h2>
        </div>
        <Card>
            <CardHeader>
                <CardTitle className="text-red-500 flex items-center">
                    <AlertTriangle className="h-5 w-5 mr-2"/>Error Loading Packet Data
                </CardTitle>
            </CardHeader>
            <CardContent>
            <p className="text-red-700 dark:text-red-400">{error}</p>
            <Button onClick={fetchPcapAndPacketData} className="mt-6"> 
                <RefreshCw className="mr-2 h-4 w-4"/>Try Again 
            </Button>
            </CardContent>
        </Card>
      </div>
    );
  }

  // Tampilan Utama Setelah Data Ter-load
  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-4">
        <div>
            <h2 className="text-2xl font-semibold tracking-tight">Packet Analysis</h2>
            {pcapFile?.metadata && (
            <p className="text-sm text-muted-foreground">
                File: {pcapFile.metadata.originalName || "Unknown file"} 
                ({pcapFile.metadata.size ? (Number(pcapFile.metadata.size) / (1024 * 1024)).toFixed(2) : "?"} MB)
            </p>
            )}
        </div>
        <div className="flex gap-2 items-center flex-wrap sm:flex-nowrap">
          {pcapFile && pcapFile.url && ( // Hanya tampilkan jika pcapFile dan URL ada
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
        <CardHeader className="border-b dark:border-gray-700 py-4 px-4 md:px-6">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div className="flex items-center gap-2 flex-grow">
                    <ListFilter className="h-5 w-5 text-muted-foreground flex-shrink-0"/>
                    <Input
                    placeholder="Filter packets (ID, IP, Port, Proto, Info...)"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    className="h-9 max-w-xs flex-grow md:max-w-sm lg:max-w-md" // Lebar dinamis
                    />
                    {filter && (
                        <Button variant="ghost" size="icon" onClick={() => setFilter("")} className="h-9 w-9 flex-shrink-0">
                            <X className="h-4 w-4" />
                        </Button>
                    )}
                </div>
                <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
                    <Select value={filterType} onValueChange={applyFilter}>
                        <SelectTrigger className="h-9 w-full xs:w-auto sm:w-[160px] md:w-[180px]"> <SelectValue placeholder="Filter by type" /> </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Packets</SelectItem>
                            <SelectItem value="TCP">TCP</SelectItem>
                            <SelectItem value="UDP">UDP</SelectItem>
                            <SelectItem value="ICMP">ICMP</SelectItem>
                            <SelectItem value="ARP">ARP</SelectItem>
                            <SelectItem value="IPv4">IPv4</SelectItem>
                            <SelectItem value="IPv6">IPv6</SelectItem>
                            <SelectItem value="tcp-reset">TCP Resets</SelectItem>
                            {/* <SelectItem value="failed-handshake">Failed Handshakes</SelectItem> */}
                            <SelectItem value="connection-issues">Packets with Errors</SelectItem>
                        </SelectContent>
                    </Select>
                    <div className="flex items-center gap-2 pt-2 sm:pt-0 whitespace-nowrap">
                        <Checkbox id="show-errors" checked={showOnlyErrors} onCheckedChange={(checked) => setShowOnlyErrors(checked as boolean)} />
                        <label htmlFor="show-errors" className="text-sm font-medium">Show only errors</label>
                    </div>
                </div>
            </div>
        </CardHeader>
        <CardContent className="p-0">
            <ScrollArea className="h-[calc(100vh-32rem)] md:h-[600px]" ref={tableContainerRef}> {/* Tingkatkan tinggi scroll area */}
                <Table className="min-w-full text-xs"> 
                    <TableHeader className="sticky top-0 z-10 bg-background shadow-sm dark:bg-slate-900">
                    <TableRow>
                        <TableHead className="w-16 px-2 py-2">No.</TableHead>
                        <TableHead className="px-2 py-2 whitespace-nowrap">Time</TableHead>
                        <TableHead className="px-2 py-2">Source</TableHead>
                        <TableHead className="px-2 py-2">Destination</TableHead>
                        <TableHead className="px-2 py-2">Protocol</TableHead>
                        <TableHead className="w-20 px-2 py-2">Length</TableHead>
                        <TableHead className="px-2 py-2 min-w-[250px] lg:min-w-[300px]">Info</TableHead>
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
                            <TableCell className="font-medium px-2 py-1.5">
                            {packet.isError && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                            {packet.id}
                            </TableCell>
                            <TableCell className="px-2 py-1.5 whitespace-nowrap">{new Date(packet.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}</TableCell>
                            <TableCell className="font-mono px-2 py-1.5">{packet.sourceIp}{packet.sourcePort ? `:${packet.sourcePort}` : ''}</TableCell>
                            <TableCell className="font-mono px-2 py-1.5">{packet.destIp}{packet.destPort ? `:${packet.destPort}` : ''}</TableCell>
                            <TableCell className="px-2 py-1.5"><Badge variant="outline" className={`${getProtocolColor(packet.protocol)} text-xs px-1.5 py-0.5 border`}>{packet.protocol}</Badge></TableCell>
                            <TableCell className="px-2 py-1.5">{packet.length} B</TableCell>
                            <TableCell className={`max-w-xs md:max-w-sm lg:max-w-md xl:max-w-lg truncate px-2 py-1.5 ${packet.isError ? "text-red-600 dark:text-red-400 font-medium" : ""}`}>
                            {packet.info}
                            </TableCell>
                        </TableRow>
                        ))
                    ) : (
                        <TableRow>
                            <TableCell colSpan={7} className="h-60 text-center text-muted-foreground">
                                {packets.length === 0 && !loading ? 
                                    <div className="flex flex-col items-center justify-center"><FileWarning className="h-10 w-10 mb-2"/>No packets were parsed for this file.</div> : 
                                    <div className="flex flex-col items-center justify-center"><Search className="h-10 w-10 mb-2"/>No packets match your current filters.</div>
                                }
                            </TableCell>
                        </TableRow>
                    )}
                    </TableBody>
                </Table>
            </ScrollArea>
            <CardFooter className="text-xs text-muted-foreground p-3 border-t dark:border-gray-700">
                Showing {filteredPackets.length.toLocaleString()} of {packets.length.toLocaleString()} packets.
                {showOnlyErrors && packets.filter((p) => p.isError).length > 0 && 
                ` (${packets.filter((p) => p.isError).length.toLocaleString()} errors found)`}
            </CardFooter>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mt-6">
        <div className="lg:col-span-3"> 
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
                <ScrollArea className="max-h-[calc(100vh-16rem)]"> {/* Disesuaikan tingginya */}
                    <CardContent className="p-0">
                        <Tabs defaultValue="details" className="w-full">
                            <TabsList className="grid w-full grid-cols-2 rounded-none border-b dark:border-gray-700">
                                <TabsTrigger value="details" className="py-2.5 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Details</TabsTrigger>
                                <TabsTrigger value="hex" className="py-2.5 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Hex View</TabsTrigger>
                            </TabsList>
                            <div className="p-4"> 
                                <TabsContent value="details" className="mt-0 text-sm space-y-2">
                                    <Accordion type="multiple" defaultValue={["Frame Information", "IPv4", "TCP", "UDP", "ICMP"]} className="w-full">
                                        {selectedPacket.detailedInfo && Object.entries(selectedPacket.detailedInfo).map(([section, detailsObj], index) => (
                                            (typeof detailsObj === 'object' && detailsObj !== null && Object.keys(detailsObj).length > 0) && ( 
                                            <AccordionItem key={section + index} value={section}>
                                                <AccordionTrigger className="text-sm font-medium hover:no-underline">{section}</AccordionTrigger>
                                                <AccordionContent className="space-y-1.5 text-xs pl-4 pt-2">
                                                {Object.entries(detailsObj).map(([key, value]) => (
                                                    <div key={key} className="grid grid-cols-[140px_1fr] gap-x-2 items-baseline"> 
                                                        <div className="font-semibold text-muted-foreground truncate" title={key}>{key}:</div>
                                                        <div className="font-mono break-all">{String(value)}</div>
                                                    </div>
                                                ))}
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
        </div> 

        <div className="lg:col-span-2"> 
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
                    <ScrollArea className="max-h-[calc(100vh-8rem)] md:max-h-[500px]"> 
                        <Table className="text-xs">
                        <TableHeader className="sticky top-0 bg-background z-10 shadow-sm dark:bg-slate-900">
                            <TableRow>
                            <TableHead className="px-2 py-2">Connection</TableHead>
                            <TableHead className="px-2 py-2">Protocol</TableHead>
                            <TableHead className="px-2 py-2">State</TableHead>
                            <TableHead className="px-2 py-2 w-20">Packets</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {connections.length > 0 ? (
                            connections.map((conn) => (
                            <TableRow key={conn.id} className={`${conn.hasErrors ? "bg-red-50 dark:bg-red-900/30 hover:bg-red-100/70 dark:hover:bg-red-800/40" : "hover:bg-muted/50 dark:hover:bg-muted/20"}`}>
                                <TableCell className="font-mono max-w-[200px] sm:max-w-xs truncate px-2 py-1.5">
                                {conn.hasErrors && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                                {`${conn.sourceIp}:${conn.sourcePort} → ${conn.destIp}:${conn.destPort}`}
                                </TableCell>
                                <TableCell className="px-2 py-1.5"><Badge variant="outline" className={`${getProtocolColor(conn.protocol)} text-xs px-1.5 py-0.5 border`}>{conn.protocol}</Badge></TableCell>
                                <TableCell className={`px-2 py-1.5 ${conn.state === "RESET" || conn.state === "CLOSED" || conn.state === "FIN_WAIT" || conn.state === "FIN_ACK" ? "text-orange-600 dark:text-orange-400" : ""}`}>
                                {conn.state}
                                </TableCell>
                                <TableCell className="px-2 py-1.5">{conn.packets.length}</TableCell>
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
        </div> 
      </div>
    </div>
  );
}
