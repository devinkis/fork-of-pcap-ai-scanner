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
  fileName?: string;
  fileSize?: string; 
  uploadDate?: string; 
  captureStartTime?: string; 
  captureEndTime?: string; 
  analysisDuration?: string; 
  analystNotes?: string; 
  dnsQueries?: { query: string, type: string, response?: string, server: string }[];
  httpRequests?: { host: string, path: string, method: string, userAgent?: string, statusCode?: number }[];
  tlsHandshakes?: { clientHello: string, serverHello: string, cipherSuite?: string, version?: string }[];
  flowData?: { flowId: string, srcIp: string, dstIp: string, srcPort: number, dstPort: number, protocol: string, packets: number, bytes: number, duration: number }[];
  fileExtracts?: { fileName: string, fileType: string, size: number, sourceIp: string, destinationIp: string, md5sum?: string, sha1sum?: string }[];
  version?: string;
  status?: 'Pending' | 'Processing' | 'Completed' | 'Error'; 
}

interface AiInsightsProps {
  analysisId: string;
  initialData?: AiInsightsData | null; 
  error?: string | null; 
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

// --- PERUBAHAN DI SINI ---
// Nama fungsi diubah dari AiInsights menjadi AIInsights (I kapital)
export default function AIInsights({ analysisId, initialData: initialServerData, error: initialError }: AiInsightsProps) {
// --- AKHIR PERUBAHAN ---
  const [data, setData] = useState<AiInsightsData | null>(initialServerData || null);
  const [isLoading, setIsLoading] = useState<boolean>(!initialServerData && !initialError);
  const [error, setError] = useState<string | null>(initialError || null);
  const [activePieIndex, setActivePieIndex] = useState<number>(0);
  const [analystNotes, setAnalystNotes] = useState<string>(initialServerData?.analystNotes || "");
  const [isSavingNotes, setIsSavingNotes] = useState<boolean>(false);
  const [showRawPayloadModal, setShowRawPayloadModal] = useState<boolean>(false);
  const [selectedPayload, setSelectedPayload] = useState<string | undefined>(undefined);
  const [currentTab, setCurrentTab] = useState<string>("summary"); 

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    console.log(`Fetching data for analysis ID: ${analysisId} at ${new Date().toLocaleTimeString()}`);
    try {
      const response = await fetch(`/api/analysis/${analysisId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: "Failed to fetch analysis data" }));
        console.error("API Error Response:", errorData);
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
      }
      const result = await response.json();
      console.log("API Success Response:", result);

      if (result && result.data && typeof result.data !== 'string') {
        setData(result.data);
        setAnalystNotes(result.data.analystNotes || "");
        // Polling logic will be handled by useEffect
      } else if (result && result.data && typeof result.data === 'string') {
        setError(`Analysis status or error: ${result.data}`);
        setData(null); 
      } else if (result && result.message) { 
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId]); 

  useEffect(() => {
    let timeoutId: NodeJS.Timeout | null = null;

    const performFetchAndPoll = async () => {
      if (!isLoading) { // Hanya fetch jika tidak sedang loading
        await fetchData(); // Tunggu fetch awal selesai
      }
    };

    if (!initialServerData && !initialError) { // Fetch jika tidak ada data server awal
        performFetchAndPoll();
    }
    
    // Set up polling if the current data (either initial or fetched) is in processing state
    // This effect will re-run if 'data' state changes.
    if (data?.status === 'Processing' || data?.status === 'Pending') {
        console.log(`Polling: Data status is ${data.status}. Will refresh in 15s.`);
        timeoutId = setTimeout(() => {
            fetchData();
        }, 15000);
    } else if (initialServerData?.status === 'Processing' || initialServerData?.status === 'Pending' && !data) {
        // Case where initial data was processing, but first fetch hasn't populated 'data' yet or failed
        console.log(`Polling: Initial server data status is ${initialServerData.status}. Will refresh in 15s.`);
        timeoutId = setTimeout(() => {
            fetchData();
        }, 15000);
    }


    return () => {
      if (timeoutId) {
        console.log("Cleaning up timeout for polling.");
        clearTimeout(timeoutId);
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchData, initialServerData, initialError, data?.status]); // data.status ditambahkan agar polling dievaluasi ulang saat status berubah


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
      console.log("Notes saved successfully");
      setData(prevData => prevData ? { ...prevData, analystNotes: analystNotes } : null);
    } catch (err: any) {
      setError(`Failed to save notes: ${err.message}`);
    } finally {
      setIsSavingNotes(false);
    }
  };

  const handleExport = (format: 'json' | 'txt' | 'csv_alerts' | 'csv_conversations') => {
    if (!data) {
        console.warn("No data to export."); // Ganti alert dengan console.warn atau toast
        return;
    }
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
          fileName += ".txt";
          contentType = "text/plain";
          break;
        case 'csv_alerts':
          if (data.alerts && data.alerts.length > 0) {
            const header = Object.keys(data.alerts[0]).map(key => `"${key.replace(/"/g, '""')}"`).join(',');
            const rows = data.alerts.map(alert => Object.values(alert).map(val => `"${String(val ?? "").replace(/"/g, '""')}"`).join(','));
            content = `${header}\n${rows.join('\n')}`;
            fileName += "_alerts.csv";
            contentType = "text/csv";
          } else {
            console.warn("No alert data to export."); // Ganti alert dengan console.warn atau toast
            return;
          }
          break;
        case 'csv_conversations':
          if (data.topConversations && data.topConversations.length > 0) {
            const header = Object.keys(data.topConversations[0]).map(key => `"${key.replace(/"/g, '""')}"`).join(',');
            const rows = data.topConversations.map(conv => Object.values(conv).map(val => `"${String(val ?? "").replace(/"/g, '""')}"`).join(','));
            content = `${header}\n${rows.join('\n')}`;
            fileName += "_conversations.csv";
            contentType = "text/csv";
          } else {
            console.warn("No conversation data to export."); // Ganti alert dengan console.warn atau toast
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
      // Ganti alert dengan console.error atau toast
      console.error(`Failed to export data: ${exportError.message}`);
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
      navigator.clipboard.writeText(window.location.href)
        .then(() => console.log("Link copied to clipboard!")) // Ganti alert dengan console atau toast
        .catch(() => console.error("Could not copy link.")); // Ganti alert dengan console atau toast
    }
  };

  const handlePrint = () => {
    window.print();
  };

  if (isLoading && !data) { // Tampilkan loading hanya jika belum ada data sama sekali
    return (
      <div className="flex flex-col items-center justify-center min-h-screen p-4">
        <div className="text-center">
          <Activity className="w-16 h-16 text-blue-500 animate-spin mx-auto mb-4" />
          <h2 className="text-2xl font-semibold mb-2">Loading Analysis Data...</h2>
          <p className="text-gray-600 dark:text-gray-300 mb-4">
            Fetching the latest insights for your PCAP file.
          </p>
          <Progress value={data?.status === 'Processing' ? 50 : (data?.status === 'Pending' ? 25 : 10)} className="w-full max-w-md mx-auto" />
           {data?.status && <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Current Status: {data.status}</p>}
          <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">Analysis ID: {analysisId}</p>
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

  if (!data) { // Jika data null setelah loading selesai (bukan karena error eksplisit)
    return (
      <Alert className="max-w-2xl mx-auto my-8">
        <Info className="h-4 w-4" />
        <AlertTitle>No Data Available</AlertTitle>
        <AlertDescription>
          <p>Analysis data could not be loaded for ID: {analysisId}. It might still be processing, or an issue occurred during fetch.</p>
           { (initialServerData?.status === 'Processing' || initialServerData?.status === 'Pending') &&
             <p className="my-2">The analysis was last known to be: <strong>{initialServerData?.status}</strong>. Please wait or try refreshing.</p>
           }
          <Button onClick={fetchData} variant="outline" className="mt-4">
            <RefreshCw className="mr-2 h-4 w-4" /> Retry Fetch
          </Button>
        </AlertDescription>
      </Alert>
    );
  }
  
  // Jika data ada, tapi statusnya masih processing, tampilkan UI utama dengan indikator loading
  if (data.status === 'Processing' || data.status === 'Pending') {
    // Optionally, show a less intrusive loading state on top of the existing data
    // For now, we'll show a prominent message if it's still processing
     return (
      <div className="flex flex-col items-center justify-center min-h-screen p-4">
        <div className="text-center">
          <Activity className="w-16 h-16 text-blue-500 animate-spin mx-auto mb-4" />
          <h2 className="text-2xl font-semibold mb-2">Analysis in Progress...</h2>
          <p className="text-gray-600 dark:text-gray-300 mb-4">
            The AI is still examining the PCAP file ({data.status}). The page will auto-refresh.
          </p>
          <Progress value={data.status === 'Processing' ? 60 : 30} className="w-full max-w-md mx-auto" />
          <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">File: {data.fileName || "N/A"}</p>
          <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">Analysis ID: {analysisId}</p>
           <Button onClick={fetchData} variant="outline" className="mt-6">
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh Now
          </Button>
        </div>
      </div>
    );
  }


  // ----- Tampilan Utama Setelah Data AI Analysis Diterima dan Selesai -----
  return (
    <TooltipProvider> 
      <div className="space-y-8 p-4 md:p-6">
        <Card className="shadow-lg hover:shadow-xl transition-shadow duration-300">
          <CardHeader className="bg-gray-50 dark:bg-gray-800 rounded-t-lg p-4 md:p-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <CardTitle className="text-xl md:text-2xl font-bold text-gray-800 dark:text-white flex items-center">
                  <FileText className="mr-2 md:mr-3 h-6 w-6 md:h-7 md:w-7 text-blue-600 dark:text-blue-400" />
                  AI Analysis: <span className="ml-1 md:ml-2 text-blue-600 dark:text-blue-400 truncate max-w-[200px] sm:max-w-xs md:max-w-md lg:max-w-lg xl:max-w-xl" title={data.fileName || "N/A"}>{data.fileName || "N/A"}</span>
                </CardTitle>
                <CardDescription className="text-xs md:text-sm text-gray-600 dark:text-gray-400 mt-1">
                  ID: {analysisId}
                </CardDescription>
              </div>
              <div className="flex space-x-1 sm:space-x-2 self-start sm:self-center">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={() => handleExport('json')} className="h-8 w-8 sm:h-9 sm:w-9">
                      <Download className="h-4 w-4" />
                      <span className="sr-only">Export JSON</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Export Full Report (JSON)</TooltipContent>
                </Tooltip>
                 <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={() => handleExport('txt')} className="h-8 w-8 sm:h-9 sm:w-9">
                      <FileText className="h-4 w-4" />
                      <span className="sr-only">Export TXT</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Export Summary (TXT)</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={handleShare} className="h-8 w-8 sm:h-9 sm:w-9">
                      <Share2 className="h-4 w-4" />
                      <span className="sr-only">Share</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Share Analysis</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={handlePrint} className="h-8 w-8 sm:h-9 sm:w-9">
                      <Printer className="h-4 w-4" />
                      <span className="sr-only">Print</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Print View</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                     <Button variant="ghost" size="icon" onClick={fetchData} disabled={isLoading} className="h-8 w-8 sm:h-9 sm:w-9">
                        <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
                        <span className="sr-only">Refresh Data</span>
                      </Button>
                  </TooltipTrigger>
                  <TooltipContent>Refresh Analysis Data</TooltipContent>
                </Tooltip>
              </div>
            </div>
            <div className="mt-3 md:mt-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-x-4 gap-y-2 text-xs md:text-sm text-gray-500 dark:text-gray-400">
                <p><strong>File Size:</strong> {data.fileSize || "N/A"}</p>
                <p><strong>Uploaded:</strong> {data.uploadDate ? new Date(data.uploadDate).toLocaleString() : "N/A"}</p>
                <p><strong>Capture Start:</strong> {data.captureStartTime ? new Date(data.captureStartTime).toLocaleString() : "N/A"}</p>
                <p><strong>Capture End:</strong> {data.captureEndTime ? new Date(data.captureEndTime).toLocaleString() : "N/A"}</p>
                <p><strong>Analysis Took:</strong> {data.analysisDuration || "N/A"}</p>
                <p><strong>Status:</strong> <span className={`font-semibold ${data.status === 'Completed' ? 'text-green-600 dark:text-green-400' : data.status === 'Error' ? 'text-red-600 dark:text-red-400' : 'text-yellow-600 dark:text-yellow-400'}`}>{data.status || "N/A"}</span></p>
            </div>
          </CardHeader>

          <CardContent className="pt-4 md:pt-6">
            <Tabs value={currentTab} onValueChange={setCurrentTab} className="w-full">
              <ScrollArea className="w-full whitespace-nowrap rounded-md border-b dark:border-gray-700">
                <TabsList className="mb-0 flex-nowrap px-1 -mx-1">
                  <TabsTrigger value="summary" className="flex items-center text-xs sm:text-sm"><Info className="mr-1 sm:mr-2 h-4 w-4" />Summary</TabsTrigger>
                  <TabsTrigger value="threats" className="flex items-center text-xs sm:text-sm"><Shield className="mr-1 sm:mr-2 h-4 w-4" />Threats</TabsTrigger>
                  <TabsTrigger value="anomalies" className="flex items-center text-xs sm:text-sm"><AlertCircle className="mr-1 sm:mr-2 h-4 w-4" />Anomalies</TabsTrigger>
                  <TabsTrigger value="recommendations" className="flex items-center text-xs sm:text-sm"><MessageSquare className="mr-1 sm:mr-2 h-4 w-4" />Actions</TabsTrigger>
                  <TabsTrigger value="visuals" className="flex items-center text-xs sm:text-sm"><BarChart2 className="mr-1 sm:mr-2 h-4 w-4" />Visuals</TabsTrigger>
                  <TabsTrigger value="conversations" className="flex items-center text-xs sm:text-sm"><Users className="mr-1 sm:mr-2 h-4 w-4" />Talkers</TabsTrigger>
                  <TabsTrigger value="alerts" className="flex items-center text-xs sm:text-sm"><AlertCircle className="mr-1 sm:mr-2 h-4 w-4" />Alerts</TabsTrigger>
                  <TabsTrigger value="packets" className="flex items-center text-xs sm:text-sm"><Maximize2 className="mr-1 sm:mr-2 h-4 w-4" />Packets</TabsTrigger>
                  {data.performanceMetrics && <TabsTrigger value="performance" className="flex items-center text-xs sm:text-sm"><Activity className="mr-1 sm:mr-2 h-4 w-4" />Perf.</TabsTrigger>}
                  {data.geoIpInformation && data.geoIpInformation.length > 0 && <TabsTrigger value="geoip" className="flex items-center text-xs sm:text-sm"><ExternalLink className="mr-1 sm:mr-2 h-4 w-4" />GeoIP</TabsTrigger>}
                  {data.attackPatterns && data.attackPatterns.length > 0 && <TabsTrigger value="attack_patterns" className="flex items-center text-xs sm:text-sm"><Shield className="mr-1 sm:mr-2 h-4 w-4" />Patterns</TabsTrigger>}
                   {data.dnsQueries && data.dnsQueries.length > 0 && <TabsTrigger value="dns" className="text-xs sm:text-sm">DNS</TabsTrigger>}
                  {data.httpRequests && data.httpRequests.length > 0 && <TabsTrigger value="http" className="text-xs sm:text-sm">HTTP</TabsTrigger>}
                  {data.tlsHandshakes && data.tlsHandshakes.length > 0 && <TabsTrigger value="tls" className="text-xs sm:text-sm">TLS</TabsTrigger>}
                  {data.flowData && data.flowData.length > 0 && <TabsTrigger value="flow" className="text-xs sm:text-sm">Flows</TabsTrigger>}
                  {data.fileExtracts && data.fileExtracts.length > 0 && <TabsTrigger value="files" className="text-xs sm:text-sm">Files</TabsTrigger>}
                </TabsList>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>

              <div className="mt-4 md:mt-6"> {/* Added padding for content below tabslist */}
                <TabsContent value="summary">
                  <Card>
                    <CardHeader><CardTitle className="flex items-center text-lg"><Info className="mr-2 text-blue-500" /> Overall Summary</CardTitle></CardHeader>
                    <CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base"><p>{data.summary || "No summary provided."}</p></CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="threats">
                  <Card>
                    <CardHeader><CardTitle className="flex items-center text-lg"><Shield className="mr-2 text-red-500" /> Threat Intelligence</CardTitle></CardHeader>
                    <CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base"><p>{data.threatAnalysis || "No specific threats identified or analysis available."}</p></CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="anomalies">
                  <Card>
                    <CardHeader><CardTitle className="flex items-center text-lg"><AlertCircle className="mr-2 text-yellow-500" /> Anomaly Detection</CardTitle></CardHeader>
                    <CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base"><p>{data.anomalyDetection || "No significant anomalies detected or analysis available."}</p></CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="recommendations">
                  <Card>
                    <CardHeader><CardTitle className="flex items-center text-lg"><MessageSquare className="mr-2 text-green-500" /> Recommended Actions</CardTitle></CardHeader>
                    <CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base"><p>{data.recommendations || "No specific recommendations available."}</p></CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="visuals" className="space-y-6">
                  {data.protocolDistribution && data.protocolDistribution.length > 0 && (
                    <Card>
                      <CardHeader><CardTitle className="flex items-center text-lg"><PieChartIcon className="mr-2 text-purple-500" /> Protocol Distribution</CardTitle></CardHeader>
                      <CardContent style={{ width: '100%', height: 300 }}>
                        <ResponsiveContainer>
                          <PieChart>
                            <Pie
                              activeIndex={activePieIndex}
                              activeShape={renderActiveShape}
                              data={data.protocolDistribution}
                              cx="50%"
                              cy="50%"
                              innerRadius={60} 
                              outerRadius={100} 
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
                </TabsContent>

                <TabsContent value="conversations">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center text-lg"><Users className="mr-2 text-indigo-500" /> Top Conversations</CardTitle>
                      <CardDescription className="text-xs sm:text-sm">
                        Key network conversations.
                        <Button variant="link" size="sm" className="ml-2 px-1 py-0 h-auto" onClick={() => handleExport('csv_conversations')}>Export CSV</Button>
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[400px] border rounded-md">
                        <Table>
                          <TableHeader><TableRow><TableHead>Src IP</TableHead><TableHead>Dst IP</TableHead><TableHead>Proto</TableHead><TableHead className="text-right">Pkts</TableHead><TableHead className="text-right">Bytes</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {data.topConversations && data.topConversations.length > 0 ? (
                              data.topConversations.map((convo) => (
                                <TableRow key={convo.id || `${convo.sourceIp}-${convo.destinationIp}-${convo.protocol}`}>
                                  <TableCell className="truncate max-w-[100px] sm:max-w-xs" title={convo.sourceIp}>{convo.sourceIp}</TableCell>
                                  <TableCell className="truncate max-w-[100px] sm:max-w-xs" title={convo.destinationIp}>{convo.destinationIp}</TableCell>
                                  <TableCell>{convo.protocol}</TableCell>
                                  <TableCell className="text-right">{convo.packets.toLocaleString()}</TableCell>
                                  <TableCell className="text-right">{convo.bytes.toLocaleString()}</TableCell>
                                </TableRow>
                              ))
                            ) : ( <TableRow><TableCell colSpan={5} className="text-center h-24">No conversation data.</TableCell></TableRow> )}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="alerts">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center text-lg"><AlertCircle className="mr-2 text-orange-500" /> Security Alerts</CardTitle>
                       <CardDescription className="text-xs sm:text-sm">Potential security events.
                        <Button variant="link" size="sm" className="ml-2 px-1 py-0 h-auto" onClick={() => handleExport('csv_alerts')}>Export CSV</Button>
                       </CardDescription>
                    </CardHeader>
                    <CardContent>
                      {data.alerts && data.alerts.length > 0 ? (
                        <Accordion type="single" collapsible className="w-full">
                          {data.alerts.map((alert) => (
                            <AccordionItem value={alert.id || alert.timestamp + alert.description.slice(0,10)} key={alert.id || alert.timestamp + alert.description.slice(0,10)}>
                              <AccordionTrigger className={`flex justify-between text-left text-sm hover:no-underline ${
                                  alert.severity === 'Critical' ? 'text-red-700 dark:text-red-400' :
                                  alert.severity === 'High' ? 'text-red-600 dark:text-red-500' :
                                  alert.severity === 'Medium' ? 'text-yellow-600 dark:text-yellow-400' :
                                  'text-blue-600 dark:text-blue-400'
                                }`}>
                                <div className="flex items-center flex-1 min-w-0">
                                  <AlertCircle className={`mr-2 h-5 w-5 flex-shrink-0 ${
                                    alert.severity === 'Critical' ? 'text-red-700 dark:text-red-400' :
                                    alert.severity === 'High' ? 'text-red-600 dark:text-red-500' :
                                    alert.severity === 'Medium' ? 'text-yellow-600 dark:text-yellow-400' :
                                    'text-blue-600 dark:text-blue-400'
                                  }`} />
                                  <span className="truncate flex-1" title={alert.description}>{alert.description}</span>
                                </div>
                                <span className={`text-xs font-medium px-2 py-0.5 rounded-md ml-2 flex-shrink-0 ${
                                  alert.severity === 'Critical' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
                                  alert.severity === 'High' ? 'bg-red-100 text-red-700 dark:bg-red-800 dark:text-red-300' :
                                  alert.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-700 dark:text-yellow-200' :
                                  'bg-blue-100 text-blue-800 dark:bg-blue-700 dark:text-blue-200'
                                }`}>{alert.severity}</span>
                              </AccordionTrigger>
                              <AccordionContent className="space-y-1 pl-8 text-xs sm:text-sm dark:bg-gray-800 rounded-b-md p-3">
                                <p><strong>Timestamp:</strong> {new Date(alert.timestamp).toLocaleString()}</p>
                                <p><strong>Full Desc:</strong> {alert.description}</p>
                                {alert.sourceIp && <p><strong>Src IP:</strong> {alert.sourceIp}</p>}
                                {alert.destinationIp && <p><strong>Dst IP:</strong> {alert.destinationIp}</p>}
                                {alert.protocol && <p><strong>Proto:</strong> {alert.protocol}</p>}
                                {alert.signature && <p><strong>Sig:</strong> {alert.signature}</p>}
                              </AccordionContent>
                            </AccordionItem>
                          ))}
                        </Accordion>
                      ) : ( <p className="text-center text-gray-500 dark:text-gray-400 py-4">No alerts to display.</p> )}
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="packets">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center text-lg"><Maximize2 className="mr-2 text-teal-500" /> Packet Samples</CardTitle>
                      <CardDescription className="text-xs sm:text-sm">Individual packet details (sample).</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[500px] border rounded-md">
                        <Table>
                          <TableHeader><TableRow><TableHead>Time</TableHead><TableHead>Src</TableHead><TableHead>Dst</TableHead><TableHead>Proto</TableHead><TableHead className="text-right">Len</TableHead><TableHead>Summary</TableHead><TableHead>Payload</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {data.detailedPacketSample && data.detailedPacketSample.length > 0 ? (
                              data.detailedPacketSample.map((packet) => (
                                <TableRow key={packet.id || packet.timestamp + packet.summary.slice(0,10)}>
                                  <TableCell className="text-xs">{new Date(packet.timestamp).toLocaleTimeString()}</TableCell>
                                  <TableCell className="truncate max-w-[80px] sm:max-w-xs" title={packet.source}>{packet.source}</TableCell>
                                  <TableCell className="truncate max-w-[80px] sm:max-w-xs" title={packet.destination}>{packet.destination}</TableCell>
                                  <TableCell>{packet.protocol}</TableCell>
                                  <TableCell className="text-right">{packet.length}</TableCell>
                                  <TableCell className="max-w-[150px] sm:max-w-xs truncate" title={packet.summary}>{packet.summary}</TableCell>
                                  <TableCell>
                                    {packet.payload && (
                                      <Button variant="link" size="sm" className="px-1 py-0 h-auto text-xs" onClick={() => {setSelectedPayload(packet.payload); setShowRawPayloadModal(true);}}>View</Button>
                                    )}
                                  </TableCell>
                                </TableRow>
                              ))
                            ) : ( <TableRow><TableCell colSpan={7} className="text-center h-24">No packet samples.</TableCell></TableRow> )}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>

                {data.performanceMetrics && (
                  <TabsContent value="performance">
                    <Card>
                      <CardHeader><CardTitle className="flex items-center text-lg"><Activity className="mr-2 text-cyan-500" /> Performance</CardTitle></CardHeader>
                      <CardContent className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-sm md:text-base">
                        <div><strong>Total Packets:</strong> {data.performanceMetrics.totalPackets.toLocaleString()}</div>
                        <div><strong>Total Bytes:</strong> {data.performanceMetrics.totalBytes.toLocaleString()}</div>
                        <div><strong>Capture Duration:</strong> {data.performanceMetrics.captureDuration}</div>
                        <div><strong>Avg Packet Rate:</strong> {data.performanceMetrics.averagePacketRate}</div>
                      </CardContent>
                    </Card>
                  </TabsContent>
                )}

                {data.geoIpInformation && data.geoIpInformation.length > 0 && (
                  <TabsContent value="geoip">
                    <Card>
                      <CardHeader><CardTitle className="flex items-center text-lg"><ExternalLink className="mr-2 text-lime-500" /> GeoIP Information</CardTitle></CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[300px] border rounded-md">
                          <Table>
                            <TableHeader><TableRow><TableHead>Src IP</TableHead><TableHead>Src Location</TableHead><TableHead>Dst IP</TableHead><TableHead>Dst Location</TableHead></TableRow></TableHeader>
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
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  </TabsContent>
                )}

                {data.attackPatterns && data.attackPatterns.length > 0 && (
                  <TabsContent value="attack_patterns">
                    <Card>
                      <CardHeader><CardTitle className="flex items-center text-lg"><Shield className="mr-2 text-rose-500" /> Attack Patterns</CardTitle></CardHeader>
                      <CardContent>
                        <Accordion type="single" collapsible className="w-full">
                          {data.attackPatterns.map((pattern, index) => (
                            <AccordionItem value={`pattern-${index}`} key={`pattern-${index}`}>
                              <AccordionTrigger className="hover:no-underline text-sm">{pattern.patternName}</AccordionTrigger>
                              <AccordionContent className="text-xs sm:text-sm dark:bg-gray-800 p-3 rounded-b-md">
                                <p className="mb-1">{pattern.description}</p>
                                <p><strong>Involved IPs:</strong> {pattern.involvedIps.join(', ')}</p>
                              </AccordionContent>
                            </AccordionItem>
                          ))}
                        </Accordion>
                      </CardContent>
                    </Card>
                  </TabsContent>
                )}
                {data.dnsQueries && data.dnsQueries.length > 0 && (
                  <TabsContent value="dns">
                    <Card><CardHeader><CardTitle className="text-lg">DNS Queries</CardTitle></CardHeader>
                    <CardContent><ScrollArea className="h-[400px] border rounded-md"><Table>
                      <TableHeader><TableRow><TableHead>Query</TableHead><TableHead>Type</TableHead><TableHead>Response</TableHead><TableHead>Server</TableHead></TableRow></TableHeader>
                      <TableBody>{data.dnsQueries.map((q, i) => (<TableRow key={i}><TableCell>{q.query}</TableCell><TableCell>{q.type}</TableCell><TableCell className="truncate max-w-[150px] sm:max-w-xs" title={q.response}>{q.response || 'N/A'}</TableCell><TableCell>{q.server}</TableCell></TableRow>))}</TableBody>
                    </Table></ScrollArea></CardContent></Card>
                  </TabsContent>
                )}

                {data.httpRequests && data.httpRequests.length > 0 && (
                  <TabsContent value="http">
                    <Card><CardHeader><CardTitle className="text-lg">HTTP Requests</CardTitle></CardHeader>
                    <CardContent><ScrollArea className="h-[400px] border rounded-md"><Table>
                      <TableHeader><TableRow><TableHead>Host</TableHead><TableHead>Path</TableHead><TableHead>Method</TableHead><TableHead>User-Agent</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
                      <TableBody>{data.httpRequests.map((r, i) => (<TableRow key={i}><TableCell className="truncate max-w-[100px] sm:max-w-xs" title={r.host}>{r.host}</TableCell><TableCell title={r.path} className="truncate max-w-[100px] sm:max-w-xs">{r.path}</TableCell><TableCell>{r.method}</TableCell><TableCell title={r.userAgent} className="truncate max-w-[100px] sm:max-w-xs">{r.userAgent || 'N/A'}</TableCell><TableCell>{r.statusCode || 'N/A'}</TableCell></TableRow>))}</TableBody>
                    </Table></ScrollArea></CardContent></Card>
                  </TabsContent>
                )}

                {data.tlsHandshakes && data.tlsHandshakes.length > 0 && (
                  <TabsContent value="tls">
                    <Card><CardHeader><CardTitle className="text-lg">TLS Handshakes</CardTitle></CardHeader>
                    <CardContent><ScrollArea className="h-[400px] border rounded-md"><Accordion type="single" collapsible className="w-full">
                      {data.tlsHandshakes.map((h, i) => (<AccordionItem value={`tls-${i}`} key={i}><AccordionTrigger className="hover:no-underline text-sm truncate">HS: {h.clientHello.substring(0,20)}... to {h.serverHello.substring(0,20)}...</AccordionTrigger><AccordionContent className="text-xs sm:text-sm dark:bg-gray-800 p-3 rounded-b-md">
                        <p><strong>Client:</strong> {h.clientHello}</p><p><strong>Server:</strong> {h.serverHello}</p>
                        <p><strong>Cipher:</strong> {h.cipherSuite || 'N/A'}</p><p><strong>Ver:</strong> {h.version || 'N/A'}</p>
                      </AccordionContent></AccordionItem>))}
                    </Accordion></ScrollArea></CardContent></Card>
                  </TabsContent>
                )}

                {data.flowData && data.flowData.length > 0 && (
                  <TabsContent value="flow">
                    <Card><CardHeader><CardTitle className="text-lg">Network Flows</CardTitle></CardHeader>
                    <CardContent><ScrollArea className="h-[400px] border rounded-md"><Table>
                      <TableHeader><TableRow><TableHead>Src IP</TableHead><TableHead>Dst IP</TableHead><TableHead>S Port</TableHead><TableHead>D Port</TableHead><TableHead>Proto</TableHead><TableHead>Pkts</TableHead><TableHead>Bytes</TableHead><TableHead>Dur(s)</TableHead></TableRow></TableHeader>
                      <TableBody>{data.flowData.map((f, i) => (<TableRow key={f.flowId || i}>
                        <TableCell>{f.srcIp}</TableCell><TableCell>{f.dstIp}</TableCell><TableCell>{f.srcPort}</TableCell><TableCell>{f.dstPort}</TableCell>
                        <TableCell>{f.protocol}</TableCell><TableCell>{f.packets}</TableCell><TableCell>{f.bytes}</TableCell><TableCell>{f.duration}</TableCell>
                      </TableRow>))}</TableBody>
                    </Table></ScrollArea></CardContent></Card>
                  </TabsContent>
                )}

                {data.fileExtracts && data.fileExtracts.length > 0 && (
                  <TabsContent value="files">
                    <Card><CardHeader><CardTitle className="text-lg">Extracted Files</CardTitle></CardHeader>
                    <CardContent><ScrollArea className="h-[400px] border rounded-md"><Table>
                      <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Size</TableHead><TableHead>Src IP</TableHead><TableHead>Dst IP</TableHead><TableHead>MD5</TableHead><TableHead>SHA1</TableHead></TableRow></TableHeader>
                      <TableBody>{data.fileExtracts.map((f, i) => (<TableRow key={i}>
                        <TableCell className="truncate max-w-[100px] sm:max-w-xs" title={f.fileName}>{f.fileName}</TableCell><TableCell>{f.fileType}</TableCell><TableCell>{f.size}</TableCell>
                        <TableCell>{f.sourceIp}</TableCell><TableCell>{f.destinationIp}</TableCell>
                        <TableCell className="font-mono text-xs truncate max-w-[80px] sm:max-w-xs" title={f.md5sum}>{f.md5sum || 'N/A'}</TableCell>
                        <TableCell className="font-mono text-xs truncate max-w-[80px] sm:max-w-xs" title={f.sha1sum}>{f.sha1sum || 'N/A'}</TableCell>
                      </TableRow>))}</TableBody>
                    </Table></ScrollArea></CardContent></Card>
                  </TabsContent>
                )}
              </div>
            </Tabs>
          </CardContent>
        </Card>

        <Card className="shadow-lg hover:shadow-xl transition-shadow duration-300">
          <CardHeader>
            <CardTitle className="flex items-center text-lg"><Edit3 className="mr-2 h-5 w-5" /> Analyst Notes</CardTitle>
            <CardDescription className="text-xs sm:text-sm">Add your observations or comments.</CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Type your notes here..."
              rows={5}
              className="mb-3 text-sm md:text-base"
            />
            <Button onClick={handleSaveNotes} disabled={isSavingNotes} size="sm">
              {isSavingNotes ? "Saving..." : "Save Notes"}
            </Button>
          </CardContent>
        </Card>

        {showRawPayloadModal && (
          <Dialog open={showRawPayloadModal} onOpenChange={setShowRawPayloadModal}>
            <DialogContent className="sm:max-w-xl md:max-w-2xl lg:max-w-4xl">
              <DialogHeader>
                <DialogTitle>Raw Packet Payload (Hex Dump)</DialogTitle>
                <DialogDescription>Hexadecimal representation of the packet payload.</DialogDescription>
              </DialogHeader>
              <ScrollArea className="max-h-[60vh] p-2 border rounded bg-gray-50 dark:bg-gray-800">
                <pre className="text-xs whitespace-pre-wrap break-all font-mono">
                  {selectedPayload || "No payload data."}
                </pre>
              </ScrollArea>
              <DialogFooter>
                <DialogClose asChild><Button type="button" variant="outline">Close</Button></DialogClose>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </TooltipProvider>
  );
}
