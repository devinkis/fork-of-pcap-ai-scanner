// components/ai-insights.tsx
"use client";

import { useState, useEffect, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, Sector } from 'recharts';
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { ExternalLink, FileText, AlertCircle, Activity, Shield, Clock, Users, BarChart2, PieChart as PieChartIcon, Info, Maximize2, Download, Share2, Printer, MessageSquare, Edit3, RefreshCw } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose,
} from "@/components/ui/dialog"
import { Textarea } from "@/components/ui/textarea"
import { Label } from "@/components/ui/label"
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
// Import yang ditambahkan untuk Tooltip
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";


// Definisikan tipe data di sini jika belum ada, atau import dari file types.ts
interface ProtocolDistribution {
  name: string;
  value: number;
  fill: string;
}

interface Conversation {
  id: string;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  packets: number;
  bytes: number;
  startTime?: string;
  endTime?: string;
  duration?: string;
}

interface AlertInfo {
  id: string;
  timestamp: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  sourceIp?: string;
  destinationIp?: string;
  protocol?: string;
  signature?: string;
}

interface DetailedPacketInfo {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  summary: string;
  payload?: string; // Hex dump of payload
}

interface AiInsightsData {
  summary?: string;
  threatAnalysis?: string;
  anomalyDetection?: string;
  recommendations?: string;
  protocolDistribution?: ProtocolDistribution[];
  topConversations?: Conversation[];
  alerts?: AlertInfo[];
  detailedPacketSample?: DetailedPacketInfo[];
  performanceMetrics?: {
    totalPackets: number;
    totalBytes: number;
    captureDuration: string;
    averagePacketRate: string;
  };
  geoIpInformation?: {
    sourceIp: string;
    destinationIp: string;
    sourceLocation?: string;
    destinationLocation?: string;
  }[];
  attackPatterns?: {
    patternName: string;
    description: string;
    involvedIps: string[];
  }[];
  // Tambahkan field baru di sini
  fileName?: string;
  fileSize?: string; // dalam format yang mudah dibaca, e.g., "1.2 MB"
  uploadDate?: string; // ISO string or formatted date
  captureStartTime?: string; // ISO string or formatted date
  captureEndTime?: string; // ISO string or formatted date
  analysisDuration?: string; // e.g., "35 seconds"
  analystNotes?: string; // for user to add notes
  dnsQueries?: { query: string, type: string, response?: string, server: string }[];
  httpRequests?: { host: string, path: string, method: string, userAgent?: string, statusCode?: number }[];
  tlsHandshakes?: { clientHello: string, serverHello: string, cipherSuite?: string, version?: string }[];
  flowData?: { flowId: string, srcIp: string, dstIp: string, srcPort: number, dstPort: number, protocol: string, packets: number, bytes: number, duration: number }[];
  fileExtracts?: { fileName: string, fileType: string, size: number, sourceIp: string, destinationIp: string, md5sum?: string, sha1sum?: string }[];
  version?: string;
  status?: 'Pending' | 'Processing' | 'Completed' | 'Error'; // Status analisis
}

interface AiInsightsProps {
  analysisId: string;
  initialData?: AiInsightsData | null; // Data awal bisa null jika fetch pertama gagal atau belum ada
  error?: string | null; // Pesan error jika ada
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82Ca9D', '#FF7F50', '#DC143C'];

const renderActiveShape = (props: any) => {
  const RADIAN = Math.PI / 180;
  const { cx, cy, midAngle, innerRadius, outerRadius, startAngle, endAngle, fill, payload, percent, value } = props;
  const sin = Math.sin(-RADIAN * midAngle);
  const cos = Math.cos(-RADIAN * midAngle);
  const sx = cx + (outerRadius + 10) * cos;
  const sy = cy + (outerRadius + 10) * sin;
  const mx = cx + (outerRadius + 30) * cos;
  const my = cy + (outerRadius + 30) * sin;
  const ex = mx + (cos >= 0 ? 1 : -1) * 22;
  const ey = my;
  const textAnchor = cos >= 0 ? 'start' : 'end';

  return (
    <g>
      <text x={cx} y={cy} dy={8} textAnchor="middle" fill={fill}>
        {payload.name}
      </text>
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
      />
      <Sector
        cx={cx}
        cy={cy}
        startAngle={startAngle}
        endAngle={endAngle}
        innerRadius={outerRadius + 6}
        outerRadius={outerRadius + 10}
        fill={fill}
      />
      <path d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`} stroke={fill} fill="none" />
      <circle cx={ex} cy={ey} r={2} fill={fill} stroke="none" />
      <text x={ex + (cos >= 0 ? 1 : -1) * 12} y={ey} textAnchor={textAnchor} fill="#333">{`${value}`}</text>
      <text x={ex + (cos >= 0 ? 1 : -1) * 12} y={ey} dy={18} textAnchor={textAnchor} fill="#999">
        {`(Rate ${(percent * 100).toFixed(2)}%)`}
      </text>
    </g>
  );
};

export default function AiInsights({ analysisId, initialData: initialServerData, error: initialError }: AiInsightsProps) {
  const [data, setData] = useState<AiInsightsData | null>(initialServerData || null);
  const [isLoading, setIsLoading] = useState<boolean>(!initialServerData && !initialError);
  const [error, setError] = useState<string | null>(initialError || null);
  const [activePieIndex, setActivePieIndex] = useState<number>(0);
  const [analystNotes, setAnalystNotes] = useState<string>(initialServerData?.analystNotes || "");
  const [isSavingNotes, setIsSavingNotes] = useState<boolean>(false);
  const [showRawPayloadModal, setShowRawPayloadModal] = useState<boolean>(false);
  const [selectedPayload, setSelectedPayload] = useState<string | undefined>(undefined);
  const [currentTab, setCurrentTab] = useState<string>("summary"); // State untuk tab aktif

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      console.log(`Workspaceing data for analysis ID: ${analysisId}`);
      const response = await fetch(`/api/analysis/${analysisId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: "Failed to fetch analysis data" }));
        console.error("API Error Response:", errorData);
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
      }
      const result = await response.json();
      console.log("API Success Response:", result);

      // Pengecekan apakah result.data ada dan bukan string
      if (result && result.data && typeof result.data !== 'string') {
        setData(result.data);
        setAnalystNotes(result.data.analystNotes || "");
        if (result.data.status === 'Processing' || result.data.status === 'Pending') {
          // Jika masih processing, set timeout untuk refresh
          setTimeout(fetchData, 15000); // Refresh setiap 15 detik
        }
      } else if (result && result.data && typeof result.data === 'string') {
        // Jika data adalah string (misalnya, pesan error atau status dari backend API OpenAI)
        setError(`Analysis status or error: ${result.data}`);
        setData(null); // Atau set state yang sesuai untuk menampilkan pesan ini
      } else if (result && result.message) { // Jika ada pesan umum
        setError(result.message);
        setData(null);
      } else {
        setError("Received unexpected data structure from API.");
        setData(null);
      }

    } catch (err: any) {
      console.error("Catch block error:", err);
      setError(err.message || "An unknown error occurred while fetching data.");
      setData(null);
    } finally {
      setIsLoading(false);
    }
  }, [analysisId]);

  useEffect(() => {
    if (!initialServerData && !initialError) { // Hanya fetch jika tidak ada data server awal
      fetchData();
    } else if (initialServerData?.status === 'Processing' || initialServerData?.status === 'Pending') {
      setTimeout(fetchData, 15000); // Mulai polling jika status awal adalah processing
    }
  }, [fetchData, initialServerData, initialError]);


  const onPieEnter = useCallback((_: any, index: number) => {
    setActivePieIndex(index);
  }, []);

  const handleSaveNotes = async () => {
    setIsSavingNotes(true);
    try {
      const response = await fetch(`/api/analysis/${analysisId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes: analystNotes }),
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: "Failed to save notes" }));
        throw new Error(errorData.message || "Failed to save notes");
      }
      // Berikan feedback sukses jika perlu
      console.log("Notes saved successfully");
      setData(prevData => prevData ? { ...prevData, analystNotes: analystNotes } : null);
    } catch (err: any) {
      setError(`Failed to save notes: ${err.message}`);
    } finally {
      setIsSavingNotes(false);
    }
  };

  const handleExport = (format: 'json' | 'txt' | 'csv_alerts' | 'csv_conversations') => {
    if (!data) return;
    let content = "";
    let fileName = `analysis_${analysisId}_${data.fileName || 'export'}`;
    let contentType = "text/plain";

    try {
      switch (format) {
        case 'json':
          content = JSON.stringify(data, null, 2);
          fileName += ".json";
          contentType = "application/json";
          break;
        case 'txt':
          content = `Analysis Report for: ${data.fileName || 'N/A'}\n`;
          content += `File Size: ${data.fileSize || 'N/A'}\n`;
          content += `Upload Date: ${data.uploadDate ? new Date(data.uploadDate).toLocaleString() : 'N/A'}\n`;
          content += `Capture Duration: ${data.performanceMetrics?.captureDuration || 'N/A'}\n\n`;
          content += `Summary:\n${data.summary || 'N/A'}\n\n`;
          content += `Threat Analysis:\n${data.threatAnalysis || 'N/A'}\n\n`;
          content += `Anomaly Detection:\n${data.anomalyDetection || 'N/A'}\n\n`;
          content += `Recommendations:\n${data.recommendations || 'N/A'}\n\n`;
          // Tambahkan detail lain jika perlu
          fileName += ".txt";
          contentType = "text/plain";
          break;
        case 'csv_alerts':
          if (data.alerts && data.alerts.length > 0) {
            const header = Object.keys(data.alerts[0]).join(',');
            const rows = data.alerts.map(alert => Object.values(alert).join(','));
            content = `${header}\n${rows.join('\n')}`;
            fileName += "_alerts.csv";
            contentType = "text/csv";
          } else {
            alert("No alert data to export.");
            return;
          }
          break;
        case 'csv_conversations':
          if (data.topConversations && data.topConversations.length > 0) {
            const header = Object.keys(data.topConversations[0]).join(',');
            const rows = data.topConversations.map(conv => Object.values(conv).join(','));
            content = `${header}\n${rows.join('\n')}`;
            fileName += "_conversations.csv";
            contentType = "text/csv";
          } else {
            alert("No conversation data to export.");
            return;
          }
          break;
      }

      const blob = new Blob([content], { type: contentType });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);

    } catch (exportError: any) {
      console.error("Export error:", exportError);
      alert(`Failed to export data: ${exportError.message}`);
    }
  };


  const handleShare = () => {
    if (navigator.share) {
      navigator.share({
        title: `PCAP Analysis: ${data?.fileName || analysisId}`,
        text: `Check out the AI-driven analysis for this PCAP file: ${data?.summary || 'No summary available.'}`,
        url: window.location.href,
      })
      .then(() => console.log('Successful share'))
      .catch((error) => console.log('Error sharing', error));
    } else {
      // Fallback untuk browser yang tidak mendukung Web Share API
      navigator.clipboard.writeText(window.location.href)
        .then(() => alert("Link copied to clipboard!"))
        .catch(() => alert("Could not copy link. Please copy it manually."));
    }
  };

  const handlePrint = () => {
    window.print();
  };


  // ----- Loading, Error, dan No Data States -----
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen p-4">
        <div className="text-center">
          <Activity className="w-16 h-16 text-blue-500 animate-spin mx-auto mb-4" />
          <h2 className="text-2xl font-semibold mb-2">Processing Analysis...</h2>
          <p className="text-gray-600 mb-4">
            The AI is meticulously examining the PCAP file. This might take a few moments, especially for larger files or complex traffic.
          </p>
          <Progress value={data?.status === 'Processing' ? 50 : 25} className="w-full max-w-md mx-auto" />
           {data?.status && <p className="mt-2 text-sm text-gray-500">Status: {data.status}</p>}
          <p className="mt-4 text-sm text-gray-500">Analysis ID: {analysisId}</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive" className="max-w-2xl mx-auto my-8">
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>Error Fetching Analysis</AlertTitle>
        <AlertDescription>
          <p>{error}</p>
          <p>Analysis ID: {analysisId}</p>
          <Button onClick={fetchData} variant="outline" className="mt-4">
            <RefreshCw className="mr-2 h-4 w-4" /> Try Again
          </Button>
        </AlertDescription>
      </Alert>
    );
  }

  if (!data) {
    return (
      <Alert className="max-w-2xl mx-auto my-8">
        <Info className="h-4 w-4" />
        <AlertTitle>No Data Available</AlertTitle>
        <AlertDescription>
          <p>Analysis data could not be loaded or is not available for ID: {analysisId}.</p>
          <Button onClick={fetchData} variant="outline" className="mt-4">
            <RefreshCw className="mr-2 h-4 w-4" /> Retry
          </Button>
        </AlertDescription>
      </Alert>
    );
  }

  // ----- Tampilan Utama Setelah Data AI Analysis Diterima -----
  // Baris 340
  return (
    <TooltipProvider> {/* Baris 341 - Sekarang sudah diimpor */}
      <div className="space-y-8"> {/* Baris 342 */}
        {/* ... (sisa JSX dari versi terakhir yang sudah diimprove UI-nya) ... */}
        {/* Card Ringkasan Analisis */}
        <Card className="shadow-lg hover:shadow-xl transition-shadow duration-300">
          <CardHeader className="bg-gray-50 dark:bg-gray-800 rounded-t-lg">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-2xl font-bold text-gray-800 dark:text-white flex items-center">
                  <FileText className="mr-3 h-7 w-7 text-blue-600" />
                  AI Analysis Report: <span className="ml-2 text-blue-600 dark:text-blue-400">{data.fileName || "N/A"}</span>
                </CardTitle>
                <CardDescription className="text-gray-600 dark:text-gray-400">
                  AI-generated insights from PCAP file. Analysis ID: {analysisId}
                </CardDescription>
              </div>
              <div className="flex space-x-2">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={() => handleExport('json')}>
                      <Download className="h-4 w-4" />
                      <span className="sr-only">Export JSON</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Export Full Report (JSON)</TooltipContent>
                </Tooltip>
                 <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={() => handleExport('txt')}>
                      <FileText className="h-4 w-4" />
                      <span className="sr-only">Export TXT</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Export Summary (TXT)</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={handleShare}>
                      <Share2 className="h-4 w-4" />
                      <span className="sr-only">Share</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Share Analysis</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={handlePrint}>
                      <Printer className="h-4 w-4" />
                      <span className="sr-only">Print</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Print View</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                     <Button variant="ghost" size="icon" onClick={fetchData} disabled={isLoading}>
                        <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
                        <span className="sr-only">Refresh Data</span>
                      </Button>
                  </TooltipTrigger>
                  <TooltipContent>Refresh Analysis Data</TooltipContent>
                </Tooltip>
              </div>
            </div>
            <div className="mt-2 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2 text-xs text-gray-500 dark:text-gray-400">
                <p><strong>File Size:</strong> {data.fileSize || "N/A"}</p>
                <p><strong>Uploaded:</strong> {data.uploadDate ? new Date(data.uploadDate).toLocaleString() : "N/A"}</p>
                <p><strong>Capture Start:</strong> {data.captureStartTime ? new Date(data.captureStartTime).toLocaleString() : "N/A"}</p>
                <p><strong>Capture End:</strong> {data.captureEndTime ? new Date(data.captureEndTime).toLocaleString() : "N/A"}</p>
                <p><strong>Analysis Took:</strong> {data.analysisDuration || "N/A"}</p>
                <p><strong>Status:</strong> <span className={`font-semibold ${data.status === 'Completed' ? 'text-green-600' : data.status === 'Error' ? 'text-red-600' : 'text-yellow-600'}`}>{data.status || "N/A"}</span></p>
            </div>
          </CardHeader>

          <CardContent className="pt-6">
            <Tabs value={currentTab} onValueChange={setCurrentTab} className="w-full">
              <ScrollArea className="w-full whitespace-nowrap rounded-md">
                <TabsList className="mb-4 flex-nowrap">
                  <TabsTrigger value="summary" className="flex items-center"><Info className="mr-2 h-4 w-4" />Summary & Overview</TabsTrigger>
                  <TabsTrigger value="threats" className="flex items-center"><Shield className="mr-2 h-4 w-4" />Threat Analysis</TabsTrigger>
                  <TabsTrigger value="anomalies" className="flex items-center"><AlertCircle className="mr-2 h-4 w-4" />Anomalies</TabsTrigger>
                  <TabsTrigger value="recommendations" className="flex items-center"><MessageSquare className="mr-2 h-4 w-4" />Recommendations</TabsTrigger>
                  <TabsTrigger value="visuals" className="flex items-center"><BarChart2 className="mr-2 h-4 w-4" />Visualizations</TabsTrigger>
                  <TabsTrigger value="conversations" className="flex items-center"><Users className="mr-2 h-4 w-4" />Conversations</TabsTrigger>
                  <TabsTrigger value="alerts" className="flex items-center"><AlertCircle className="mr-2 h-4 w-4" />Alerts</TabsTrigger>
                  <TabsTrigger value="packets" className="flex items-center"><Maximize2 className="mr-2 h-4 w-4" />Packet Samples</TabsTrigger>
                  {data.performanceMetrics && <TabsTrigger value="performance" className="flex items-center"><Activity className="mr-2 h-4 w-4" />Performance</TabsTrigger>}
                  {data.geoIpInformation && data.geoIpInformation.length > 0 && <TabsTrigger value="geoip" className="flex items-center"><ExternalLink className="mr-2 h-4 w-4" />GeoIP</TabsTrigger>}
                  {data.attackPatterns && data.attackPatterns.length > 0 && <TabsTrigger value="attack_patterns" className="flex items-center"><Shield className="mr-2 h-4 w-4" />Attack Patterns</TabsTrigger>}
                   {data.dnsQueries && data.dnsQueries.length > 0 && <TabsTrigger value="dns">DNS Queries</TabsTrigger>}
                  {data.httpRequests && data.httpRequests.length > 0 && <TabsTrigger value="http">HTTP Requests</TabsTrigger>}
                  {data.tlsHandshakes && data.tlsHandshakes.length > 0 && <TabsTrigger value="tls">TLS Handshakes</TabsTrigger>}
                  {data.flowData && data.flowData.length > 0 && <TabsTrigger value="flow">Flow Data</TabsTrigger>}
                  {data.fileExtracts && data.fileExtracts.length > 0 && <TabsTrigger value="files">File Extracts</TabsTrigger>}
                </TabsList>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>


              {/* Tab Content: Summary */}
              <TabsContent value="summary">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center"><Info className="mr-2 text-blue-500" /> Overall Summary</CardTitle>
                  </CardHeader>
                  <CardContent className="prose dark:prose-invert max-w-none">
                    <p>{data.summary || "No summary provided."}</p>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab Content: Threat Analysis */}
              <TabsContent value="threats">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center"><Shield className="mr-2 text-red-500" /> Threat Intelligence</CardTitle>
                  </CardHeader>
                  <CardContent className="prose dark:prose-invert max-w-none">
                    <p>{data.threatAnalysis || "No specific threats identified or analysis available."}</p>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab Content: Anomaly Detection */}
              <TabsContent value="anomalies">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center"><AlertCircle className="mr-2 text-yellow-500" /> Anomaly Detection</CardTitle>
                  </CardHeader>
                  <CardContent className="prose dark:prose-invert max-w-none">
                    <p>{data.anomalyDetection || "No significant anomalies detected or analysis available."}</p>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab Content: Recommendations */}
              <TabsContent value="recommendations">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center"><MessageSquare className="mr-2 text-green-500" /> Recommendations</CardTitle>
                  </CardHeader>
                  <CardContent className="prose dark:prose-invert max-w-none">
                    <p>{data.recommendations || "No specific recommendations available."}</p>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab Content: Visualizations */}
              <TabsContent value="visuals" className="space-y-6">
                {data.protocolDistribution && data.protocolDistribution.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center"><PieChartIcon className="mr-2 text-purple-500" /> Protocol Distribution</CardTitle>
                    </CardHeader>
                    <CardContent style={{ width: '100%', height: 400 }}>
                      <ResponsiveContainer>
                        <PieChart>
                          <Pie
                            activeIndex={activePieIndex}
                            activeShape={renderActiveShape}
                            data={data.protocolDistribution}
                            cx="50%"
                            cy="50%"
                            innerRadius={80} // Meningkatkan innerRadius agar tidak terlalu tipis
                            outerRadius={120} // Meningkatkan outerRadius
                            fill="#8884d8"
                            dataKey="value"
                            onMouseEnter={onPieEnter}
                          >
                            {data.protocolDistribution.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.fill || COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <RechartsTooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                )}
                 {/* Add other charts here if needed, e.g., traffic over time */}
              </TabsContent>

              {/* Tab Content: Top Conversations */}
              <TabsContent value="conversations">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center"><Users className="mr-2 text-indigo-500" /> Top Conversations</CardTitle>
                    <CardDescription>
                      Key network conversations identified in the PCAP.
                       <Button variant="outline" size="sm" className="ml-2" onClick={() => handleExport('csv_conversations')}>Export Conversations (CSV)</Button>
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[400px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Source IP</TableHead>
                            <TableHead>Destination IP</TableHead>
                            <TableHead>Protocol</TableHead>
                            <TableHead className="text-right">Packets</TableHead>
                            <TableHead className="text-right">Bytes</TableHead>
                            <TableHead>Start Time</TableHead>
                            <TableHead>End Time</TableHead>
                            <TableHead>Duration</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {data.topConversations && data.topConversations.length > 0 ? (
                            data.topConversations.map((convo) => (
                              <TableRow key={convo.id || `${convo.sourceIp}-${convo.destinationIp}-${convo.protocol}`}>
                                <TableCell>{convo.sourceIp}</TableCell>
                                <TableCell>{convo.destinationIp}</TableCell>
                                <TableCell>{convo.protocol}</TableCell>
                                <TableCell className="text-right">{convo.packets}</TableCell>
                                <TableCell className="text-right">{convo.bytes}</TableCell>
                                <TableCell>{convo.startTime ? new Date(convo.startTime).toLocaleString() : 'N/A'}</TableCell>
                                <TableCell>{convo.endTime ? new Date(convo.endTime).toLocaleString() : 'N/A'}</TableCell>
                                <TableCell>{convo.duration || 'N/A'}</TableCell>
                              </TableRow>
                            ))
                          ) : (
                            <TableRow>
                              <TableCell colSpan={8} className="text-center">No conversation data available.</TableCell>
                            </TableRow>
                          )}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab Content: Alerts */}
              <TabsContent value="alerts">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center"><AlertCircle className="mr-2 text-orange-500" /> Security Alerts</CardTitle>
                     <CardDescription>
                      Potential security events and notable observations.
                       <Button variant="outline" size="sm" className="ml-2" onClick={() => handleExport('csv_alerts')}>Export Alerts (CSV)</Button>
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {data.alerts && data.alerts.length > 0 ? (
                      <Accordion type="single" collapsible className="w-full">
                        {data.alerts.map((alert) => (
                          <AccordionItem value={alert.id || alert.timestamp + alert.description.slice(0,10)} key={alert.id || alert.timestamp + alert.description.slice(0,10)}>
                            <AccordionTrigger className={`flex justify-between ${
                                alert.severity === 'Critical' ? 'text-red-700 dark:text-red-500' :
                                alert.severity === 'High' ? 'text-red-600 dark:text-red-400' :
                                alert.severity === 'Medium' ? 'text-yellow-600 dark:text-yellow-400' :
                                'text-blue-600 dark:text-blue-400'
                              }`}>
                              <div className="flex items-center">
                                <AlertCircle className={`mr-2 h-5 w-5 ${
                                  alert.severity === 'Critical' ? 'text-red-700' :
                                  alert.severity === 'High' ? 'text-red-600' :
                                  alert.severity === 'Medium' ? 'text-yellow-600' :
                                  'text-blue-600'
                                }`} />
                                <span>{alert.description.substring(0, 80)}{alert.description.length > 80 && '...'}</span>
                              </div>
                              <span className={`text-sm font-medium px-2 py-1 rounded-md ${
                                alert.severity === 'Critical' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
                                alert.severity === 'High' ? 'bg-red-100 text-red-700 dark:bg-red-800 dark:text-red-300' :
                                alert.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-700 dark:text-yellow-200' :
                                'bg-blue-100 text-blue-800 dark:bg-blue-700 dark:text-blue-200'
                              }`}>{alert.severity}</span>
                            </AccordionTrigger>
                            <AccordionContent className="space-y-1 pl-8 text-sm">
                              <p><strong>Timestamp:</strong> {new Date(alert.timestamp).toLocaleString()}</p>
                              <p><strong>Description:</strong> {alert.description}</p>
                              {alert.sourceIp && <p><strong>Source IP:</strong> {alert.sourceIp}</p>}
                              {alert.destinationIp && <p><strong>Destination IP:</strong> {alert.destinationIp}</p>}
                              {alert.protocol && <p><strong>Protocol:</strong> {alert.protocol}</p>}
                              {alert.signature && <p><strong>Signature/Rule:</strong> {alert.signature}</p>}
                            </AccordionContent>
                          </AccordionItem>
                        ))}
                      </Accordion>
                    ) : (
                      <p>No alerts to display.</p>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab Content: Detailed Packet Sample */}
              <TabsContent value="packets">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center"><Maximize2 className="mr-2 text-teal-500" /> Detailed Packet Samples</CardTitle>
                    <CardDescription>A sample of individual packets for closer inspection.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[500px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Timestamp</TableHead>
                            <TableHead>Source</TableHead>
                            <TableHead>Destination</TableHead>
                            <TableHead>Protocol</TableHead>
                            <TableHead className="text-right">Length</TableHead>
                            <TableHead>Summary</TableHead>
                            <TableHead>Payload</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {data.detailedPacketSample && data.detailedPacketSample.length > 0 ? (
                            data.detailedPacketSample.map((packet) => (
                              <TableRow key={packet.id || packet.timestamp + packet.summary.slice(0,10)}>
                                <TableCell>{new Date(packet.timestamp).toLocaleString()}</TableCell>
                                <TableCell>{packet.source}</TableCell>
                                <TableCell>{packet.destination}</TableCell>
                                <TableCell>{packet.protocol}</TableCell>
                                <TableCell className="text-right">{packet.length}</TableCell>
                                <TableCell className="max-w-xs truncate">{packet.summary}</TableCell>
                                <TableCell>
                                  {packet.payload && (
                                    <Button variant="link" size="sm" onClick={() => {setSelectedPayload(packet.payload); setShowRawPayloadModal(true);}}>View Payload</Button>
                                  )}
                                </TableCell>
                              </TableRow>
                            ))
                          ) : (
                            <TableRow>
                              <TableCell colSpan={7} className="text-center">No packet samples available.</TableCell>
                            </TableRow>
                          )}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab Content: Performance Metrics */}
              {data.performanceMetrics && (
                <TabsContent value="performance">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center"><Activity className="mr-2 text-cyan-500" /> Performance Metrics</CardTitle>
                    </CardHeader>
                    <CardContent className="grid grid-cols-2 gap-4">
                      <div><strong>Total Packets:</strong> {data.performanceMetrics.totalPackets.toLocaleString()}</div>
                      <div><strong>Total Bytes:</strong> {data.performanceMetrics.totalBytes.toLocaleString()}</div>
                      <div><strong>Capture Duration:</strong> {data.performanceMetrics.captureDuration}</div>
                      <div><strong>Average Packet Rate:</strong> {data.performanceMetrics.averagePacketRate}</div>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}

              {/* Tab Content: GeoIP Information */}
              {data.geoIpInformation && data.geoIpInformation.length > 0 && (
                <TabsContent value="geoip">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center"><ExternalLink className="mr-2 text-lime-500" /> GeoIP Information</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Source IP</TableHead>
                            <TableHead>Source Location</TableHead>
                            <TableHead>Destination IP</TableHead>
                            <TableHead>Destination Location</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {data.geoIpInformation.map((geo, index) => (
                            <TableRow key={`${geo.sourceIp}-${geo.destinationIp}-${index}`}>
                              <TableCell>{geo.sourceIp}</TableCell>
                              <TableCell>{geo.sourceLocation || 'N/A'}</TableCell>
                              <TableCell>{geo.destinationIp}</TableCell>
                              <TableCell>{geo.destinationLocation || 'N/A'}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}

              {/* Tab Content: Attack Patterns */}
              {data.attackPatterns && data.attackPatterns.length > 0 && (
                <TabsContent value="attack_patterns">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center"><Shield className="mr-2 text-rose-500" /> Known Attack Patterns</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <Accordion type="single" collapsible className="w-full">
                        {data.attackPatterns.map((pattern, index) => (
                          <AccordionItem value={`pattern-${index}`} key={`pattern-${index}`}>
                            <AccordionTrigger>{pattern.patternName}</AccordionTrigger>
                            <AccordionContent>
                              <p className="mb-2">{pattern.description}</p>
                              <p><strong>Involved IPs:</strong> {pattern.involvedIps.join(', ')}</p>
                            </AccordionContent>
                          </AccordionItem>
                        ))}
                      </Accordion>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}
              {/* DNS Queries Tab */}
              {data.dnsQueries && data.dnsQueries.length > 0 && (
                <TabsContent value="dns">
                  <Card>
                    <CardHeader><CardTitle>DNS Queries</CardTitle></CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[400px]">
                        <Table>
                          <TableHeader><TableRow><TableHead>Query</TableHead><TableHead>Type</TableHead><TableHead>Response</TableHead><TableHead>Server</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {data.dnsQueries.map((q, i) => (
                              <TableRow key={i}><TableCell>{q.query}</TableCell><TableCell>{q.type}</TableCell><TableCell>{q.response || 'N/A'}</TableCell><TableCell>{q.server}</TableCell></TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}

              {/* HTTP Requests Tab */}
              {data.httpRequests && data.httpRequests.length > 0 && (
                <TabsContent value="http">
                  <Card>
                    <CardHeader><CardTitle>HTTP Requests</CardTitle></CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[400px]">
                        <Table>
                          <TableHeader><TableRow><TableHead>Host</TableHead><TableHead>Path</TableHead><TableHead>Method</TableHead><TableHead>User-Agent</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {data.httpRequests.map((r, i) => (
                              <TableRow key={i}><TableCell>{r.host}</TableCell><TableCell title={r.path} className="max-w-xs truncate">{r.path}</TableCell><TableCell>{r.method}</TableCell><TableCell title={r.userAgent} className="max-w-xs truncate">{r.userAgent || 'N/A'}</TableCell><TableCell>{r.statusCode || 'N/A'}</TableCell></TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}

              {/* TLS Handshakes Tab */}
              {data.tlsHandshakes && data.tlsHandshakes.length > 0 && (
                <TabsContent value="tls">
                  <Card>
                    <CardHeader><CardTitle>TLS Handshakes</CardTitle></CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[400px]">
                        <Accordion type="single" collapsible className="w-full">
                          {data.tlsHandshakes.map((h, i) => (
                            <AccordionItem value={`tls-${i}`} key={i}>
                              <AccordionTrigger>Handshake: {h.clientHello.substring(0,30)}... to {h.serverHello.substring(0,30)}...</AccordionTrigger>
                              <AccordionContent>
                                <p><strong>Client Hello:</strong> {h.clientHello}</p>
                                <p><strong>Server Hello:</strong> {h.serverHello}</p>
                                <p><strong>Cipher Suite:</strong> {h.cipherSuite || 'N/A'}</p>
                                <p><strong>TLS Version:</strong> {h.version || 'N/A'}</p>
                              </AccordionContent>
                            </AccordionItem>
                          ))}
                        </Accordion>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}

              {/* Flow Data Tab */}
              {data.flowData && data.flowData.length > 0 && (
                <TabsContent value="flow">
                  <Card>
                    <CardHeader><CardTitle>Network Flows</CardTitle></CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[400px]">
                        <Table>
                          <TableHeader><TableRow><TableHead>Src IP</TableHead><TableHead>Dst IP</TableHead><TableHead>Src Port</TableHead><TableHead>Dst Port</TableHead><TableHead>Proto</TableHead><TableHead>Packets</TableHead><TableHead>Bytes</TableHead><TableHead>Duration (s)</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {data.flowData.map((f, i) => (
                              <TableRow key={f.flowId || i}>
                                <TableCell>{f.srcIp}</TableCell><TableCell>{f.dstIp}</TableCell>
                                <TableCell>{f.srcPort}</TableCell><TableCell>{f.dstPort}</TableCell>
                                <TableCell>{f.protocol}</TableCell><TableCell>{f.packets}</TableCell>
                                <TableCell>{f.bytes}</TableCell><TableCell>{f.duration}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}

              {/* File Extracts Tab */}
              {data.fileExtracts && data.fileExtracts.length > 0 && (
                <TabsContent value="files">
                  <Card>
                    <CardHeader><CardTitle>Extracted Files</CardTitle></CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[400px]">
                        <Table>
                          <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Size</TableHead><TableHead>Source IP</TableHead><TableHead>Dest IP</TableHead><TableHead>MD5</TableHead><TableHead>SHA1</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {data.fileExtracts.map((f, i) => (
                              <TableRow key={i}>
                                <TableCell>{f.fileName}</TableCell><TableCell>{f.fileType}</TableCell>
                                <TableCell>{f.size}</TableCell><TableCell>{f.sourceIp}</TableCell>
                                <TableCell>{f.destinationIp}</TableCell>
                                <TableCell className="font-mono text-xs">{f.md5sum || 'N/A'}</TableCell>
                                <TableCell className="font-mono text-xs">{f.sha1sum || 'N/A'}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}

            </Tabs>
          </CardContent>
        </Card>

        {/* Analyst Notes Section */}
        <Card className="shadow-lg hover:shadow-xl transition-shadow duration-300">
          <CardHeader>
            <CardTitle className="flex items-center"><Edit3 className="mr-2 h-5 w-5" /> Analyst Notes</CardTitle>
            <CardDescription>Add your observations or comments about this analysis.</CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Type your notes here..."
              rows={6}
              className="mb-4"
            />
            <Button onClick={handleSaveNotes} disabled={isSavingNotes}>
              {isSavingNotes ? "Saving..." : "Save Notes"}
            </Button>
          </CardContent>
        </Card>

        {/* Raw Payload Modal */}
        {showRawPayloadModal && (
          <Dialog open={showRawPayloadModal} onOpenChange={setShowRawPayloadModal}>
            <DialogContent className="sm:max-w-[600px]">
              <DialogHeader>
                <DialogTitle>Raw Packet Payload (Hex Dump)</DialogTitle>
                <DialogDescription>
                  This is the hexadecimal representation of the packet payload.
                </DialogDescription>
              </DialogHeader>
              <ScrollArea className="max-h-[400px] p-2 border rounded">
                <pre className="text-xs whitespace-pre-wrap break-all">
                  {selectedPayload || "No payload data."}
                </pre>
              </ScrollArea>
              <DialogFooter>
                <DialogClose asChild>
                  <Button type="button" variant="outline">Close</Button>
                </DialogClose>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </TooltipProvider>
  );
}
