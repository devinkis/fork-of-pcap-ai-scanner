// components/ai-insights.tsx
"use client";

import React, { useState, useEffect, useCallback } from "react";
// ... (impor lainnya)
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, Sector } from 'recharts';
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { ExternalLink, FileText, AlertCircle, Activity, Shield, Clock, Users, BarChart2, PieChart as PieChartIcon, Info, Maximize2, Download, Share2, Printer, MessageSquare, Edit3, RefreshCw, Loader2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogClose,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
// --- PERBAIKAN MULAI ---
import { Badge } from "@/components/ui/badge"; // Tambahkan impor ini
// --- PERBAIKAN SELESAI ---


// ... (sisa interface dan fungsi helper seperti renderActiveShape tetap sama) ...
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
  payload?: string;
}

interface AiInsightsData {
  summary?: string;
  threatAnalysis?: string;
  anomalyDetection?: string;
  recommendations?: string | Array<{ title?: string; description?: string; priority?: string; }>;
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
  status?: 'Pending' | 'Processing' | 'Completed' | 'Error' | 'UNKNOWN';
  threatLevel?: string;
  findings?: Array<{ id?: string; title?: string; description?: string; severity?: string; confidence?: number; recommendation?: string; category?: string; affectedHosts?: string[]; relatedPackets?: number[]; }>;
  iocs?: Array<{ type?: string; value?: string; context?: string; confidence?: number; }>;
  statistics?: any;
  timeline?: Array<{ time?: string; event?: string; severity?: string; }>;
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


export function AIInsights({ analysisId, initialData: initialServerData, error: initialError }: AiInsightsProps) {
  const [data, setData] = useState<AiInsightsData | null>(initialServerData || null);
  const [isLoading, setIsLoading] = useState<boolean>(true); 
  const [error, setError] = useState<string | null>(initialError || null);
  const [activePieIndex, setActivePieIndex] = useState<number>(0);
  const [analystNotes, setAnalystNotes] = useState<string>(""); 
  const [isSavingNotes, setIsSavingNotes] = useState<boolean>(false);
  const [showRawPayloadModal, setShowRawPayloadModal] = useState<boolean>(false);
  const [selectedPayload, setSelectedPayload] = useState<string | undefined>(undefined);
  const [currentTab, setCurrentTab] = useState<string>("summary");

  const fetchData = useCallback(async (isRetry = false) => {
    if (!isRetry) { 
        setIsLoading(true);
    }
    setError(null); 
    console.log(`[AI_INSIGHTS] Fetching AI analysis data for ID: ${analysisId} at ${new Date().toLocaleTimeString()}`);
    try {
      const response = await fetch(`/api/analyze-pcap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ analysisId: analysisId }),
      });

      const result = await response.json(); 

      if (!response.ok) {
        console.error("[AI_INSIGHTS] API Error Response:", result);
        throw new Error(result.error || result.message || `HTTP error! status: ${response.status}`);
      }
      
      console.log("[AI_INSIGHTS] API Success Response:", result);

      if (result && result.success && result.analysis) {
        const analysisData = result.analysis;
        setData(prevData => ({
          fileName: prevData?.fileName || analysisData.fileName || initialServerData?.fileName,
          fileSize: prevData?.fileSize || analysisData.fileSize || initialServerData?.fileSize,
          uploadDate: prevData?.uploadDate || analysisData.uploadDate || initialServerData?.uploadDate,
          ...analysisData, 
          status: 'Completed', 
          analystNotes: analysisData.analystNotes || prevData?.analystNotes || initialServerData?.analystNotes || "",
        }));
        setAnalystNotes(analysisData.analystNotes || data?.analystNotes || initialServerData?.analystNotes || "");
      } else if (result && result.error) {
        setError(result.error);
        setData(prevData => ({ ...prevData, status: 'Error' } as AiInsightsData));
      } else {
        setError("Received unexpected data structure from AI analysis API.");
        setData(prevData => ({ ...prevData, status: 'Error' } as AiInsightsData));
      }

    } catch (err: any) {
      console.error("[AI_INSIGHTS] Catch block error in fetchData:", err);
      setError(err.message || "An unknown error occurred while fetching AI analysis.");
      setData(prevData => ({ ...prevData, status: 'Error' } as AiInsightsData));
    } finally {
      setIsLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId]); 

  useEffect(() => {
    if (initialServerData && !initialError) { // Periksa juga initialError
      console.log("[AI_INSIGHTS] Using initial server data.");
      setData(initialServerData);
      setAnalystNotes(initialServerData.analystNotes || "");
      setIsLoading(false);
    } else if (initialError) {
      console.log("[AI_INSIGHTS] Using initial server error.");
      setError(initialError);
      setIsLoading(false);
    } else if (!data && analysisId) { // Hanya fetch jika data belum ada dan analysisId ada
      console.log("[AI_INSIGHTS] No initial data or error, performing initial fetch for analysisId:", analysisId);
      fetchData(); 
    } else if (data && !isLoading){ // Jika sudah ada data dan tidak loading, tidak perlu fetch
      console.log("[AI_INSIGHTS] Data already exists, no initial fetch needed or loading already completed.");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId, initialServerData, initialError]); // Hanya fetchData yang dihilangkan dari dependency array untuk mencegah loop fetch


  const onPieEnter = useCallback((_: any, index: number) => {
    setActivePieIndex(index);
  }, []);

  const handleSaveNotes = async () => {
    setIsSavingNotes(true);
    setError(null); 
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
      const saveData = await response.json();
      console.log("Notes saved successfully:", saveData);
      setData(prevData => prevData ? { ...prevData, analystNotes: analystNotes } : null);
      alert("Notes saved!"); 
    } catch (err: any) {
      console.error("Error saving notes:", err);
      setError(`Failed to save notes: ${err.message}`);
    } finally {
      setIsSavingNotes(false);
    }
  };

  const handleExport = (format: 'json' | 'txt' | 'csv_alerts' | 'csv_conversations') => {
    if (!data) {
        console.warn("No data to export.");
        alert("No data available to export.");
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
          content += `Recommendations:\n`;
          if (Array.isArray(data.recommendations)) {
            data.recommendations.forEach(rec => {
                content += `- ${rec.title || 'Recommendation'}: ${rec.description || ''} (Priority: ${rec.priority || 'N/A'})\n`;
            });
          } else if (typeof data.recommendations === 'string') {
            content += data.recommendations;
          } else {
            content += 'N/A';
          }
          content += '\n\n';
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
            alert("No alert data available to export.");
            return;
          }
          break;
        case 'csv_conversations':
          const conversationsToExport = data.topConversations || (data.statistics?.topTalkers && data.statistics.topTalkers[0]?.ip !== "No identifiable IP traffic" ? data.statistics.topTalkers : []);
          if (conversationsToExport && conversationsToExport.length > 0) {
            const header = Object.keys(conversationsToExport[0]).map(key => `"${key.replace(/"/g, '""')}"`).join(',');
            const rows = conversationsToExport.map((conv:any) => Object.values(conv).map(val => `"${String(val ?? "").replace(/"/g, '""')}"`).join(','));
            content = `${header}\n${rows.join('\n')}`;
            fileName += "_conversations.csv";
            contentType = "text/csv";
          } else {
             alert("No conversation data available to export.");
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
      navigator.clipboard.writeText(window.location.href)
        .then(() => alert("Link copied to clipboard!")) 
        .catch(() => alert("Could not copy link.")); 
    }
  };

  const handlePrint = () => {
    window.print();
  };

  if (isLoading && !data) { 
    return (
      <div className="flex flex-col items-center justify-center min-h-[300px] p-4">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-blue-500 animate-spin mx-auto mb-4" /> {/* Ganti ikon Activity menjadi Loader2 */}
          <h2 className="text-xl font-semibold mb-2">Loading AI Insights...</h2>
          <p className="text-gray-600 dark:text-gray-300 mb-4">
            The AI is analyzing your PCAP data. This might take a few moments.
          </p>
          <Progress value={30} className="w-full max-w-md mx-auto" />
          <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Analysis ID: {analysisId}</p>
        </div>
      </div>
    );
  }

  if (error && !isLoading && (!data || data.status === 'Error')) {
    return (
      <Alert variant="destructive" className="max-w-2xl mx-auto my-8">
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>Error Fetching Analysis</AlertTitle>
        <AlertDescription>
          <p>{error}</p>
          <p>Analysis ID: {analysisId}</p>
          <Button onClick={() => fetchData(true)} variant="outline" className="mt-4" disabled={isLoading}>
            <RefreshCw className="mr-2 h-4 w-4" /> {isLoading ? "Retrying..." : "Try Again"}
          </Button>
        </AlertDescription>
      </Alert>
    );
  }
  
  if (!data && !isLoading) { 
    return (
      <Alert className="max-w-2xl mx-auto my-8">
        <Info className="h-4 w-4" />
        <AlertTitle>No AI Insights Available</AlertTitle>
        <AlertDescription>
          <p>AI insights could not be loaded for analysis ID: {analysisId}. The analysis might still be processing, the ID could be invalid, or an issue occurred during the fetch.</p>
           <Button onClick={() => fetchData(true)} variant="outline" className="mt-4" disabled={isLoading}>
            <RefreshCw className="mr-2 h-4 w-4" /> {isLoading ? "Refreshing..." : "Refresh"}
          </Button>
        </AlertDescription>
      </Alert>
    );
  }
  
  return (
    <TooltipProvider> 
      <div className="space-y-8 p-4 md:p-6">
        {/* ... (sisa JSX untuk menampilkan data, sama seperti sebelumnya) ... */}
        {error && data && data.status !== 'Error' && (
             <Alert variant="destructive" className="mb-6">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>An Issue Occurred</AlertTitle>
                <AlertDescription>
                 {error}
                  <Button onClick={() => fetchData(true)} variant="outline" size="sm" className="mt-2 ml-2" disabled={isLoading}>
                    <RefreshCw className="mr-2 h-3 w-3" /> {isLoading ? "Retrying..." : "Try Again"}
                  </Button>
                </AlertDescription>
            </Alert>
        )}

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
                  <TooltipContent><p>Export Full Report (JSON)</p></TooltipContent>
                </Tooltip>
                 <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={() => handleExport('txt')} className="h-8 w-8 sm:h-9 sm:w-9">
                      <FileText className="h-4 w-4" />
                      <span className="sr-only">Export TXT</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent><p>Export Summary (TXT)</p></TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={handleShare} className="h-8 w-8 sm:h-9 sm:w-9">
                      <Share2 className="h-4 w-4" />
                      <span className="sr-only">Share</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent><p>Share Analysis</p></TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" onClick={handlePrint} className="h-8 w-8 sm:h-9 sm:w-9">
                      <Printer className="h-4 w-4" />
                      <span className="sr-only">Print</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent><p>Print View</p></TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                     <Button variant="ghost" size="icon" onClick={() => fetchData(true)} disabled={isLoading} className="h-8 w-8 sm:h-9 sm:w-9">
                        <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
                        <span className="sr-only">Refresh Data</span>
                      </Button>
                  </TooltipTrigger>
                  <TooltipContent><p>Refresh Analysis Data</p></TooltipContent>
                </Tooltip>
              </div>
            </div>
            <div className="mt-3 md:mt-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-x-4 gap-y-2 text-xs md:text-sm text-gray-500 dark:text-gray-400">
                <p><strong>File Size:</strong> {data.fileSize || "N/A"}</p>
                <p><strong>Uploaded:</strong> {data.uploadDate ? new Date(data.uploadDate).toLocaleString() : "N/A"}</p>
                <p><strong>Analysis Status:</strong> <Badge variant={getStatusVariant(data.status)}>{data.status || "UNKNOWN"}</Badge></p>
                <p><strong>Threat Level:</strong> <Badge variant={
                    data.threatLevel?.toLowerCase() === 'critical' || data.threatLevel?.toLowerCase() === 'high' ? 'destructive' :
                    data.threatLevel?.toLowerCase() === 'medium' ? 'default' : 'outline'
                }>{data.threatLevel || "N/A"}</Badge></p>
            </div>
          </CardHeader>

          <CardContent className="pt-4 md:pt-6">
            <Tabs value={currentTab} onValueChange={setCurrentTab} className="w-full">
              <ScrollArea className="w-full whitespace-nowrap rounded-md border-b dark:border-gray-700">
                <TabsList className="mb-0 flex-nowrap px-1 -mx-1">
                  <TabsTrigger value="summary" className="flex items-center text-xs sm:text-sm"><Info className="mr-1 sm:mr-2 h-4 w-4" />Summary</TabsTrigger>
                  <TabsTrigger value="threats" className="flex items-center text-xs sm:text-sm"><Shield className="mr-1 sm:mr-2 h-4 w-4" />Threats & IOCs</TabsTrigger>
                  <TabsTrigger value="recommendations" className="flex items-center text-xs sm:text-sm"><MessageSquare className="mr-1 sm:mr-2 h-4 w-4" />Actions</TabsTrigger>
                  <TabsTrigger value="timeline" className="flex items-center text-xs sm:text-sm"><Clock className="mr-1 sm:mr-2 h-4 w-4" />Timeline</TabsTrigger>
                  <TabsTrigger value="visuals" className="flex items-center text-xs sm:text-sm"><BarChart2 className="mr-1 sm:mr-2 h-4 w-4" />Visuals</TabsTrigger>
                  {data.performanceMetrics && <TabsTrigger value="performance" className="flex items-center text-xs sm:text-sm"><Activity className="mr-1 sm:mr-2 h-4 w-4" />Perf.</TabsTrigger>}
                  {/* Tambahkan tab lain jika ada datanya */}
                </TabsList>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>

              <div className="mt-4 md:mt-6">
                <TabsContent value="summary">
                  <Card>
                    <CardHeader><CardTitle className="flex items-center text-lg"><Info className="mr-2 text-blue-500" /> Overall Summary</CardTitle></CardHeader>
                    <CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base"><p>{data.summary || "No summary provided by AI."}</p></CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="threats">
                    {/* ... (konten tab threats seperti sebelumnya, pastikan Badge diimpor) ... */}
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center text-lg">
                                <Shield className="mr-2 text-red-500" /> Threat Intelligence & IOCs
                                {data.threatLevel && (
                                    <Badge variant={
                                        data.threatLevel.toLowerCase() === 'critical' || data.threatLevel.toLowerCase() === 'high' ? 'destructive' :
                                        data.threatLevel.toLowerCase() === 'medium' ? 'default' : 'outline'
                                    } className="ml-3 text-xs">
                                        Threat Level: {data.threatLevel}
                                    </Badge>
                                )}
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div>
                                <h3 className="font-semibold mb-2 text-base">Threat Analysis:</h3>
                                <p className="prose dark:prose-invert max-w-none text-sm md:text-base">{data.threatAnalysis || "No specific threat analysis provided by AI."}</p>
                            </div>
                            {data.findings && data.findings.length > 0 && (
                                <div>
                                    <h3 className="font-semibold mt-4 mb-2 text-base">Specific Findings:</h3>
                                    <Accordion type="single" collapsible className="w-full">
                                        {data.findings.map((finding,idx) => (
                                            <AccordionItem value={finding.id || `finding-${idx}`} key={finding.id || `finding-${idx}`}>
                                                <AccordionTrigger className="text-sm hover:no-underline text-left">{finding.title || "Untitled Finding"} <Badge variant="outline" className="ml-2 text-xs">{finding.severity || 'N/A'}</Badge></AccordionTrigger>
                                                <AccordionContent className="text-xs space-y-1 pl-4">
                                                    <p><strong>Description:</strong> {finding.description}</p>
                                                    <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                                                    <p><strong>Category:</strong> {finding.category}</p>
                                                    {finding.affectedHosts && finding.affectedHosts.length > 0 && <p><strong>Affected Hosts:</strong> {finding.affectedHosts.join(', ')}</p>}
                                                    {finding.relatedPackets && finding.relatedPackets.length > 0 && <p><strong>Related Packet Samples (No.):</strong> {finding.relatedPackets.join(', ')}</p>}
                                                    <p><strong>Confidence:</strong> {finding.confidence !== undefined ? `${finding.confidence}%` : 'N/A'}</p>
                                                </AccordionContent>
                                            </AccordionItem>
                                        ))}
                                    </Accordion>
                                </div>
                            )}
                             {data.iocs && data.iocs.length > 0 && (
                                <div>
                                    <h3 className="font-semibold mt-6 mb-2 text-base">Indicators of Compromise (IOCs):</h3>
                                    <ScrollArea className="h-auto max-h-[300px] border rounded-md">
                                        <Table className="text-xs">
                                            <TableHeader><TableRow><TableHead>Type</TableHead><TableHead>Value</TableHead><TableHead>Context</TableHead><TableHead>Confidence</TableHead></TableRow></TableHeader>
                                            <TableBody>
                                            {data.iocs.map((ioc, index) => (
                                                <TableRow key={index}>
                                                <TableCell>{ioc.type || 'N/A'}</TableCell>
                                                <TableCell className="font-mono truncate max-w-[150px]" title={ioc.value}>{ioc.value || 'N/A'}</TableCell>
                                                <TableCell className="truncate max-w-[200px]" title={ioc.context}>{ioc.context || 'N/A'}</TableCell>
                                                <TableCell>{ioc.confidence !== undefined ? `${ioc.confidence}%` : 'N/A'}</TableCell>
                                                </TableRow>
                                            ))}
                                            </TableBody>
                                        </Table>
                                    </ScrollArea>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="recommendations">
                  {/* ... (konten tab recommendations seperti sebelumnya) ... */}
                   <Card>
                    <CardHeader><CardTitle className="flex items-center text-lg"><MessageSquare className="mr-2 text-green-500" /> Recommended Actions</CardTitle></CardHeader>
                    <CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base">
                         {data.recommendations && Array.isArray(data.recommendations) && data.recommendations.length > 0 ? (
                            <ul className="list-disc pl-5 space-y-2">
                                {data.recommendations.map((rec, index) => (
                                <li key={index}>
                                    <strong className="font-medium">{rec.title || `Recommendation ${index + 1}`}</strong> (Priority: {rec.priority || 'N/A'}):
                                    <p className="text-sm ml-4">{rec.description || "No detailed description."}</p>
                                </li>
                                ))}
                            </ul>
                        ) : (
                            <p>{typeof data.recommendations === 'string' ? data.recommendations : "No specific recommendations provided by AI."}</p>
                        )}
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="timeline">
                    {/* ... (konten tab timeline seperti sebelumnya) ... */}
                    <Card>
                        <CardHeader><CardTitle className="flex items-center text-lg"><Clock className="mr-2 text-fuchsia-500" /> Event Timeline</CardTitle></CardHeader>
                        <CardContent>
                            {data.timeline && data.timeline.length > 0 ? (
                                <div className="relative pl-6 space-y-6 border-l-2 border-gray-200 dark:border-gray-700">
                                    {data.timeline.map((event, index) => (
                                        <div key={index} className="relative">
                                            <div className={`absolute -left-[calc(0.75rem+1px)] mt-1.5 flex h-6 w-6 items-center justify-center rounded-full ${
                                                event.severity === 'error' ? 'bg-red-500' : event.severity === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
                                            } text-white text-xs font-semibold`}>
                                                {event.severity === 'error' ? <AlertCircle size={14}/> : event.severity === 'warning' ? <AlertTriangle size={14}/> : <Info size={14}/>}
                                            </div>
                                            <div className="ml-4">
                                                <p className="font-medium text-sm">{event.event || "Unknown Event"}</p>
                                                <p className="text-xs text-muted-foreground">
                                                    {event.time && !event.time.includes("Packet Sample") ? new Date(event.time).toLocaleString() : event.time || "N/A"}
                                                </p>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <p className="text-center text-gray-500 dark:text-gray-400 py-4">No timeline events provided by AI.</p>
                            )}
                        </CardContent>
                    </Card>
                </TabsContent>

                 <TabsContent value="visuals" className="space-y-6">
                   {/* ... (konten tab visuals seperti sebelumnya) ... */}
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
                             <Legend layout="vertical" align="right" verticalAlign="middle" iconSize={10} wrapperStyle={{fontSize: "12px"}}/>
                          </PieChart>
                        </ResponsiveContainer>
                      </CardContent>
                    </Card>
                  )}
                  {data.statistics?.topTalkers && data.statistics.topTalkers.length > 0 && data.statistics.topTalkers[0].ip !== "No identifiable IP traffic" && (
                    <Card>
                        <CardHeader><CardTitle className="flex items-center text-lg"><BarChart2 className="mr-2 text-green-500"/> Top Talkers (by Packets)</CardTitle></CardHeader>
                        <CardContent style={{ width: '100%', height: 300 }}>
                            <ResponsiveContainer>
                                <BarChart data={data.statistics.topTalkers} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                                    <CartesianGrid strokeDasharray="3 3" />
                                    <XAxis type="number" />
                                    <YAxis dataKey="ip" type="category" width={150} interval={0} tick={{ fontSize: 10 }}/>
                                    <RechartsTooltip />
                                    <Legend wrapperStyle={{fontSize: "12px"}}/>
                                    <Bar dataKey="packets" name="Total Packets" fill="#82ca9d" />
                                </BarChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                  )}
                </TabsContent>
                {/* ... (Sisa TabsContent lainnya) ... */}
              </div>
            </Tabs>
          </CardContent>
        </Card>

        <Card className="shadow-lg hover:shadow-xl transition-shadow duration-300">
          {/* ... (konten Analyst Notes seperti sebelumnya) ... */}
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
              {isSavingNotes ? (<><Loader2 className="mr-2 h-4 w-4 animate-spin"/>Saving...</>) : "Save Notes"}
            </Button>
          </CardContent>
        </Card>

        {showRawPayloadModal && (
          // ... (konten Dialog Raw Payload seperti sebelumnya) ...
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
