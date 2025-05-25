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
    FileWarning, FileText, ListFilter, Info, Search, // Pastikan Search diimpor
    Network as ConnectionIcon, Maximize2, Minimize2
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
// --- IMPOR ALERT DAN TOOLTIP ---
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"; 
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";


// Interface (Packet, Connection, BlobFile, PacketAnalysisProps) tetap sama
// ... (kode interface Packet, Connection, BlobFile, PacketAnalysisProps) ...
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
  const [isDetailMaximized, setIsDetailMaximized] = useState(false);
  const tableContainerRef = useRef<HTMLDivElement>(null);

  const fetchPcapAndPacketData = async () => {
    // ... (fungsi ini tetap sama seperti versi terakhir) ...
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
      } else if (!pcapInfoData.success) {
        console.warn("API /api/get-pcap did not return success or no files found:", pcapInfoData.error || "No files returned");
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
    // ... (logika filter tetap sama) ...
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
      typeMatch = packet.errorType === "Failed Handshake"; 
    } else if (filterType === "connection-issues") {
      typeMatch = packet.isError === true && !!packet.errorType;
    } else if (filterType !== "all" && packet.protocol) { 
        typeMatch = packet.protocol.toUpperCase().includes(filterType.toUpperCase());
    }
    return textMatch && errorMatch && typeMatch;
  });

  const getProtocolColor = (protocol?: string) => { 
    // ... (fungsi ini tetap sama) ...
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
    // ... (fungsi ini tetap sama) ...
    if (packet.isError) return "bg-red-50 dark:bg-red-900/20 hover:bg-red-100/70 dark:hover:bg-red-800/40";
    if (selectedPacket?.id === packet.id) return "bg-primary/10 dark:bg-primary/20"; 
    return "hover:bg-muted/50 dark:hover:bg-muted/30";
  };

  const downloadPcapFile = async () => { /* ... (fungsi ini tetap sama) ... */ };
  const handlePacketClick = (packet: Packet) => { setSelectedPacket(packet); };
  const applyFilter = (type: string) => { setFilterType(type); };

  // ... (Kode untuk state loading dan error tetap sama seperti versi terakhir)
  if (loading && packets.length === 0) {
     return (
      <div className="space-y-6 animate-pulse">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 mb-4">
            <Skeleton className="h-8 w-48" />
            <div className="flex gap-2 items-center">
                <Skeleton className="h-9 w-36" /> 
                <Skeleton className="h-9 w-24" /> 
            </div>
        </div>
        <Skeleton className="h-5 w-3/4 mb-4" /> 
        
        <Card className="shadow-md">
            <CardHeader className="border-b dark:border-slate-700 py-3 px-4 md:px-6">
                <Skeleton className="h-9 w-full" /> 
            </CardHeader>
            <CardContent className="p-0">
                <ScrollArea className="h-[calc(100vh-28rem)] md:h-[500px]">
                     <div className="p-4 space-y-2"> 
                        {[...Array(15)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
                     </div>
                </ScrollArea>
            </CardContent>
            <CardFooter className="p-3 border-t dark:border-slate-700">
                <Skeleton className="h-4 w-48"/>
            </CardFooter>
        </Card>
      </div>
     );
  }

  if (error && !loading) { 
    return (
      <div className="space-y-6 p-4 md:p-6 lg:p-8">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 mb-4">
            <h1 className="text-2xl font-semibold tracking-tight text-red-600 dark:text-red-400">Packet Analysis Error</h1>
        </div>
        <Alert variant="destructive" className="shadow-md">
            <AlertTriangle className="h-5 w-5" />
            <AlertTitle className="text-lg">Could Not Load Packet Data</AlertTitle>
            <AlertDescription className="mt-2 space-y-3">
                <p>{error}</p>
                <Button onClick={fetchPcapAndPacketData} className="mt-2"> 
                    <RefreshCw className="mr-2 h-4 w-4"/>Try Again 
                </Button>
            </AlertDescription>
        </Alert>
      </div>
    );
  }
  // ----- Tampilan Utama Setelah Data Ter-load -----
  // Baris 271
  return (
    <TooltipProvider> {/* Baris 272 - Sekarang sudah diimpor */}
      <div className="space-y-6"> {/* Baris 273 */}
        {/* ... (sisa JSX dari versi terakhir yang sudah diimprove UI-nya) ... */}
        {/* Header Halaman */}
      <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 pb-4 border-b dark:border-slate-700">
        <div>
            <h1 className="text-3xl font-bold tracking-tight">Packet Analysis</h1>
            {pcapFile?.metadata && (
            <p className="text-sm text-muted-foreground mt-1">
                File: <span className="font-medium text-foreground">{pcapFile.metadata.originalName || "Unknown file"}</span> 
                ({pcapFile.metadata.size ? (Number(pcapFile.metadata.size) / (1024 * 1024)).toFixed(2) : "?"} MB)
            </p>
            )}
        </div>
        <div className="flex gap-2 items-center flex-shrink-0 flex-wrap sm:flex-nowrap">
          {pcapFile && pcapFile.url && ( 
            <Tooltip>
                <TooltipTrigger asChild>
                    <Button variant="outline" size="sm" onClick={downloadPcapFile} className="w-full xs:w-auto">
                    <FileDown className="h-4 w-4 mr-2" />
                    Download PCAP
                    </Button>
                </TooltipTrigger>
                <TooltipContent><p>Download the original PCAP file</p></TooltipContent>
            </Tooltip>
          )}
           <Tooltip>
                <TooltipTrigger asChild>
                    <Button variant="default" size="sm" onClick={fetchPcapAndPacketData} disabled={loading} className="w-full xs:w-auto">
                    <RefreshCw className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
                    {loading ? "Refreshing..." : "Refresh Data"}
                    </Button>
                </TooltipTrigger>
                <TooltipContent><p>Reload packet data from the server</p></TooltipContent>
           </Tooltip>
        </div>
      </header>

      {/* Filter Bar dalam Card */}
      <Card className="shadow-lg border dark:border-slate-700">
        <CardHeader className="border-b dark:border-slate-700 py-3 px-4 md:px-6">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 md:gap-4">
                <div className="flex items-center gap-2 flex-grow min-w-0"> 
                    <ListFilter className="h-5 w-5 text-muted-foreground flex-shrink-0"/>
                    <Input
                    placeholder="Filter packets (ID, IP, Port, Protocol, Info...)"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    className="h-9 text-sm flex-grow min-w-[150px] sm:max-w-xs md:max-w-sm lg:max-w-md" 
                    />
                    {filter && (
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <Button variant="ghost" size="icon" onClick={() => setFilter("")} className="h-9 w-9 flex-shrink-0">
                                    <X className="h-4 w-4" />
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent><p>Clear filter</p></TooltipContent>
                        </Tooltip>
                    )}
                </div>
                <div className="flex items-center gap-3 flex-wrap sm:flex-nowrap"> 
                    <Select value={filterType} onValueChange={applyFilter}>
                        <SelectTrigger className="h-9 w-full xs:w-auto sm:w-[160px] md:w-[180px] text-sm"> 
                            <SelectValue placeholder="Filter by type" /> 
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Packets</SelectItem>
                            <SelectItem value="TCP">TCP</SelectItem>
                            <SelectItem value="UDP">UDP</SelectItem>
                            <SelectItem value="ICMP">ICMP</SelectItem>
                            <SelectItem value="ARP">ARP</SelectItem>
                            <SelectItem value="IPv4">IPv4</SelectItem>
                            <SelectItem value="IPv6">IPv6</SelectItem>
                            <SelectItem value="tcp-reset">TCP Resets</SelectItem>
                            <SelectItem value="connection-issues">Packets with Errors</SelectItem>
                        </SelectContent>
                    </Select>
                    <div className="flex items-center gap-2 pt-2 sm:pt-0 whitespace-nowrap">
                        <Checkbox id="show-errors" checked={showOnlyErrors} onCheckedChange={(checked) => setShowOnlyErrors(checked as boolean)} />
                        <label htmlFor="show-errors" className="text-sm font-medium cursor-pointer">Show only errors</label>
                    </div>
                </div>
            </div>
        </CardHeader>
        {/* Tabel Paket */}
        <CardContent className="p-0"> 
            <ScrollArea className="h-[60vh] min-h-[400px]" ref={tableContainerRef}> 
                <Table className="min-w-[800px] text-xs"> 
                    <TableHeader className="sticky top-0 z-10 bg-background/95 backdrop-blur-sm dark:bg-slate-800/95">
                    <TableRow>
                        <TableHead className="w-16 px-3 py-2.5">No.</TableHead>
                        <TableHead className="px-3 py-2.5 whitespace-nowrap">Time</TableHead>
                        <TableHead className="px-3 py-2.5">Source</TableHead>
                        <TableHead className="px-3 py-2.5">Destination</TableHead>
                        <TableHead className="px-3 py-2.5">Protocol</TableHead>
                        <TableHead className="w-20 px-3 py-2.5">Length</TableHead>
                        <TableHead className="px-3 py-2.5 min-w-[300px]">Info</TableHead>
                    </TableRow>
                    </TableHeader>
                    <TableBody>
                    {filteredPackets.length > 0 ? (
                        filteredPackets.map((packet) => (
                        <TableRow
                            key={packet.id}
                            className={`${getRowClassName(packet)} cursor-pointer transition-colors duration-150`}
                            onClick={() => handlePacketClick(packet)}
                            data-packet-id={packet.id}
                        >
                            <TableCell className="font-medium px-3 py-2">
                            {packet.isError && <AlertTriangle className="h-3.5 w-3.5 text-red-500 inline mr-1.5" />}
                            {packet.id}
                            </TableCell>
                            <TableCell className="px-3 py-2 whitespace-nowrap">{new Date(packet.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}</TableCell>
                            <TableCell className="font-mono px-3 py-2">{packet.sourceIp}{packet.sourcePort ? `:${packet.sourcePort}` : ''}</TableCell>
                            <TableCell className="font-mono px-3 py-2">{packet.destIp}{packet.destPort ? `:${packet.destPort}` : ''}</TableCell>
                            <TableCell className="px-3 py-2"><Badge variant="outline" className={`${getProtocolColor(packet.protocol)} text-xs px-2 py-0.5 border`}>{packet.protocol}</Badge></TableCell>
                            <TableCell className="px-3 py-2">{packet.length} B</TableCell>
                            <TableCell className={`max-w-xs md:max-w-md lg:max-w-lg xl:max-w-xl truncate px-3 py-2 ${packet.isError ? "text-red-600 dark:text-red-400 font-semibold" : ""}`}>
                            {packet.info}
                            </TableCell>
                        </TableRow>
                        ))
                    ) : (
                        <TableRow>
                            <TableCell colSpan={7} className="h-60 text-center text-muted-foreground">
                                {packets.length === 0 && !loading ? 
                                    <div className="flex flex-col items-center justify-center py-10"><FileWarning className="h-12 w-12 mb-3 text-gray-400"/><p>No packets were parsed for this file.</p></div> : 
                                    <div className="flex flex-col items-center justify-center py-10"><Search className="h-12 w-12 mb-3 text-gray-400"/><p>No packets match your current filters.</p></div>
                                }
                            </TableCell>
                        </TableRow>
                    )}
                    </TableBody>
                </Table>
            </ScrollArea>
            <CardFooter className="text-xs text-muted-foreground p-3 border-t dark:border-slate-700">
                Showing {filteredPackets.length.toLocaleString()} of {packets.length.toLocaleString()} packets.
                {showOnlyErrors && packets.filter((p) => p.isError).length > 0 && 
                ` (${packets.filter((p) => p.isError).length.toLocaleString()} errors found)`}
            </CardFooter>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-7 gap-x-6 gap-y-6 mt-6">
        <div className={`${selectedPacket || isDetailMaximized ? 'xl:col-span-4' : 'hidden xl:block xl:col-span-4'} ${isDetailMaximized ? 'fixed inset-0 z-50 bg-background p-4 overflow-y-auto xl:relative xl:p-0' : 'relative'} transition-all duration-300 ease-in-out`}> 
            {selectedPacket || isDetailMaximized && selectedPacket ? ( 
            <Card className={`shadow-xl flex flex-col ${isDetailMaximized ? 'h-full' : 'sticky top-6 max-h-[calc(100vh-7rem)]'}`}> 
                <CardHeader className="pb-2 border-b dark:border-slate-700 flex-shrink-0">
                <div className="flex justify-between items-center">
                    <CardTitle className="text-lg">Packet #{selectedPacket?.id} Details</CardTitle> 
                    <div className="flex items-center gap-1">
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <Button variant="ghost" size="icon" onClick={() => setIsDetailMaximized(!isDetailMaximized)} className="h-7 w-7">
                                    {isDetailMaximized ? <Minimize2 className="h-4 w-4"/> : <Maximize2 className="h-4 w-4"/>}
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent><p>{isDetailMaximized ? "Restore" : "Maximize"} Detail View</p></TooltipContent>
                        </Tooltip>
                        <Tooltip>
                             <TooltipTrigger asChild>
                                <Button variant="ghost" size="icon" onClick={() => {setSelectedPacket(null); setIsDetailMaximized(false);}} className="h-7 w-7">
                                    <X className="h-4 w-4"/>
                                </Button>
                             </TooltipTrigger>
                             <TooltipContent><p>Close Detail View</p></TooltipContent>
                        </Tooltip>
                    </div>
                </div>
                <CardDescription className="text-xs mt-1">Timestamp: {selectedPacket?.timestamp ? new Date(selectedPacket.timestamp).toLocaleString() : 'N/A'}</CardDescription>
                </CardHeader>
                <ScrollArea className="flex-grow min-h-0"> 
                    <CardContent className="p-0"> 
                        <Tabs defaultValue="details" className="w-full">
                            <TabsList className="grid w-full grid-cols-2 rounded-none border-b dark:border-slate-700">
                                <TabsTrigger value="details" className="py-2.5 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:text-primary data-[state=active]:shadow-none rounded-none">Details</TabsTrigger>
                                <TabsTrigger value="hex" className="py-2.5 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:text-primary data-[state=active]:shadow-none rounded-none">Hex View</TabsTrigger>
                            </TabsList>
                            <div className="p-4 text-xs"> 
                                <TabsContent value="details" className="mt-0 space-y-2">
                                    <Accordion type="multiple" defaultValue={["Frame Information", "IPv4", "TCP", "UDP", "ICMP"]} className="w-full">
                                        {selectedPacket?.detailedInfo && Object.entries(selectedPacket.detailedInfo).map(([section, detailsObj], index) => (
                                            (typeof detailsObj === 'object' && detailsObj !== null && Object.keys(detailsObj).length > 0) && ( 
                                            <AccordionItem key={section + index} value={section} className="border-b dark:border-slate-700 last:border-b-0">
                                                <AccordionTrigger className="text-xs font-semibold hover:no-underline py-2.5 px-1 text-left">
                                                    {section}
                                                </AccordionTrigger>
                                                <AccordionContent className="space-y-1.5 pl-5 pt-1 pb-2 text-xs">
                                                {Object.entries(detailsObj).map(([key, value]) => (
                                                    <div key={key} className="grid grid-cols-[minmax(100px,max-content)_1fr] gap-x-2 items-baseline"> 
                                                        <div className="font-semibold text-muted-foreground break-words whitespace-nowrap" title={key}>{key}:</div>
                                                        <div className="font-mono break-all">{String(value)}</div>
                                                    </div>
                                                ))}
                                                </AccordionContent>
                                            </AccordionItem>
                                            )
                                        ))}
                                    </Accordion>
                                    {selectedPacket?.isError && selectedPacket?.errorType && (
                                        <Alert variant="destructive" className="mt-4">
                                            <AlertTriangle className="h-4 w-4" />
                                            <AlertTitle className="text-sm">Error: {selectedPacket.errorType}</AlertTitle>
                                            <AlertDescription className="text-xs">An error or anomaly was detected for this packet.</AlertDescription>
                                        </Alert>
                                    )}
                                </TabsContent>
                                <TabsContent value="hex" className="mt-0">
                                    <ScrollArea className="h-[300px] max-h-[calc(100vh-25rem)] w-full rounded-md border p-3 bg-muted/30 dark:bg-slate-800">
                                        <pre className="font-mono text-xs whitespace-pre-wrap break-all"> 
                                            {(selectedPacket?.hexDump && selectedPacket.hexDump.length > 0) 
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
            <Card className="shadow-lg sticky top-6">
                <CardHeader>
                    <CardTitle className="text-lg flex items-center"><FileText className="mr-2 h-5 w-5 text-muted-foreground"/>Packet Details</CardTitle>
                </CardHeader>
                <CardContent className="text-center py-16 text-muted-foreground">
                    <Info className="h-10 w-10 mx-auto mb-3 text-gray-400" />
                    <p className="text-sm">Select a packet from the list to view its details.</p>
                </CardContent>
            </Card>
            )}
        </div> 

        <div className={`${isDetailMaximized ? 'hidden xl:hidden' : 'xl:col-span-3'} space-y-6 transition-all duration-300 ease-in-out`}> 
            <Card className="shadow-lg">
                <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center">
                    <ConnectionIcon className="mr-2 h-5 w-5 text-muted-foreground"/>Connection Summary
                </CardTitle>
                <CardDescription>
                    {connections.length.toLocaleString()} connections detected
                    {connections.filter((c) => c.hasErrors).length > 0 && 
                    ` (${connections.filter((c) => c.hasErrors).length.toLocaleString()} with errors)`}
                </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                    <ScrollArea className="max-h-[calc(100vh-12rem)] md:max-h-[450px]"> 
                        <Table className="text-xs">
                        <TableHeader className="sticky top-0 bg-background z-10 shadow-sm dark:bg-slate-800">
                            <TableRow>
                            <TableHead className="px-3 py-2.5">Connection</TableHead>
                            <TableHead className="px-3 py-2.5">Protocol</TableHead>
                            <TableHead className="px-3 py-2.5">State</TableHead>
                            <TableHead className="px-3 py-2.5 w-20">Packets</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {connections.length > 0 ? (
                            connections.map((conn) => (
                            <TableRow key={conn.id} className={`${conn.hasErrors ? "bg-red-50 dark:bg-red-900/30 hover:bg-red-100/70 dark:hover:bg-red-800/40" : "hover:bg-muted/50 dark:hover:bg-muted/30"}`}>
                                <TableCell className="font-mono max-w-[180px] sm:max-w-xs truncate px-3 py-2">
                                {conn.hasErrors && <AlertTriangle className="h-3.5 w-3.5 text-red-500 inline mr-1.5" />}
                                {`${conn.sourceIp}:${conn.sourcePort} → ${conn.destIp}:${conn.destPort}`}
                                </TableCell>
                                <TableCell className="px-3 py-2"><Badge variant="outline" className={`${getProtocolColor(conn.protocol)} text-xs px-2 py-0.5 border`}>{conn.protocol}</Badge></TableCell>
                                <TableCell className={`px-3 py-2 ${conn.state === "RESET" || conn.state === "CLOSED" || conn.state === "FIN_WAIT" || conn.state === "FIN_ACK" ? "text-orange-600 dark:text-orange-400" : ""}`}>
                                {conn.state}
                                </TableCell>
                                <TableCell className="px-3 py-2">{conn.packets.length}</TableCell>
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
    </TooltipProvider>
  );
}
