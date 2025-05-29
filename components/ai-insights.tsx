// components/ai-insights.tsx
"use client";

import React, { useState, useEffect, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, Sector } from 'recharts';
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { 
  ExternalLink, FileText, AlertCircle, Activity, Shield, Clock, Users, 
  BarChart2, PieChart as PieChartIcon, Info, Maximize2, Download, 
  Share2, Printer, MessageSquare, Edit3, RefreshCw, Loader2, AlertTriangle, Siren,
  Server as ServerIcon, User as UserIcon, ArrowRight, XCircle as XCircleIcon, Zap // Tambahkan ikon
} from 'lucide-react';
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
import { Badge } from "@/components/ui/badge";
import { IOCList } from "@/components/ioc-list";

// --- Definisi Interface ---
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

interface IOC {
  type: "ip" | "domain" | "url" | "hash";
  value: string;
  context: string;
  confidence: number;
}

interface ErrorAnalysisDetail {
  errorType: string;
  count: number;
  description: string;
  possibleCauses: string[];
  troubleshootingSuggestions: string[];
  relatedPacketSamples?: number[];
}

interface SamplePacketForContext {
  no: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  isError?: boolean;
  errorType?: string;
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
  iocs?: IOC[];
  statistics?: any;
  timeline?: Array<{ time?: string; event?: string; severity?: string; }>;
  trafficBehaviorScore?: { score: number; justification: string; };
  errorAnalysisReport?: ErrorAnalysisDetail[];
  samplePacketsForContext?: SamplePacketForContext[]; // Ditambahkan
}

interface AiInsightsProps {
  analysisId: string;
  initialData?: AiInsightsData | null;
  error?: string | null;
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82Ca9D', '#FF7F50', '#DC143C'];
const getStatusVariant = (status?: string): "default" | "secondary" | "destructive" | "outline" => { switch(status?.toLowerCase()){case"completed":return"default";case"processing":case"pending":return"secondary";case"error":return"destructive";default:return"outline"}};
const renderActiveShape = (props: any) => { const RADIAN=Math.PI/180;const{cx,cy,midAngle,innerRadius,outerRadius,startAngle,endAngle,fill,payload,percent,value}=props;const sin=Math.sin(-RADIAN*midAngle);const cos=Math.cos(-RADIAN*midAngle);const sx=cx+(outerRadius+10)*cos;const sy=cy+(outerRadius+10)*sin;const mx=cx+(outerRadius+30)*cos;const my=cy+(outerRadius+30)*sin;const ex=mx+(cos>=0?1:-1)*22;const ey=my;const textAnchor=cos>=0?"start":"end";return(<g><text x={cx}y={cy}dy={8}textAnchor="middle"fill={fill}>{payload.name}</text><Sector cx={cx}cy={cy}innerRadius={innerRadius}outerRadius={outerRadius}startAngle={startAngle}endAngle={endAngle}fill={fill}/><Sector cx={cx}cy={cy}startAngle={startAngle}endAngle={endAngle}innerRadius={outerRadius+6}outerRadius={outerRadius+10}fill={fill}/><path d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`}stroke={fill}fill="none"/><circle cx={ex}cy={ey}r={2}fill={fill}stroke="none"/><text x={ex+(cos>=0?1:-1)*12}y={ey}textAnchor={textAnchor}fill="#333">{`${value}`}</text><text x={ex+(cos>=0?1:-1)*12}y={ey}dy={18}textAnchor={textAnchor}fill="#999">{`(Rate ${(percent*100).toFixed(2)}%)`}</text></g>)};

// --- Komponen Animasi TCP Reset (Dasar) ---
interface TcpResetAnimationProps {
  clientIp?: string; // IP yang memulai koneksi (biasanya)
  serverIp?: string; // IP yang merespons atau dihubungi
  resetInitiatorIp?: string; // IP yang mengirim RST
  packetInfo?: string;
}

const TcpResetAnimation: React.FC<TcpResetAnimationProps> = ({ clientIp, serverIp, resetInitiatorIp, packetInfo }) => {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const timeouts: NodeJS.Timeout[] = [];
    if (step === 0) { // Otomatis mulai animasi saat komponen dimuat (jika visible)
        timeouts.push(setTimeout(() => setStep(1), 500));    // SYN
        timeouts.push(setTimeout(() => setStep(2), 1500));   // SYN-ACK
        timeouts.push(setTimeout(() => setStep(3), 2500));   // ACK
        timeouts.push(setTimeout(() => setStep(4), 3500));   // Data (opsional, bisa di-skip)
        timeouts.push(setTimeout(() => setStep(5), 4500));   // RST
    }
    return () => timeouts.forEach(clearTimeout);
  }, [step]);

  const getIpRole = (ip?: string) => {
    if (!ip) return "Unknown";
    if (ip === clientIp && ip === resetInitiatorIp) return `${ip} (Client, Sent RST)`;
    if (ip === serverIp && ip === resetInitiatorIp) return `${ip} (Server, Sent RST)`;
    if (ip === clientIp) return `${ip} (Client)`;
    if (ip === serverIp) return `${ip} (Server)`;
    return ip;
  }

  const isResetFromClient = clientIp === resetInitiatorIp;

  return (
    <div className="p-4 space-y-3 min-h-[300px] flex flex-col items-center justify-center bg-slate-50 dark:bg-slate-800/50 rounded-md border">
      <p className="text-sm text-center text-muted-foreground mb-3">
        Illustrative flow for: {packetInfo || "TCP Reset"}
      </p>
      <div className="flex justify-around w-full items-start mb-4">
        <div className="text-center w-1/3">
          <UserIcon size={32} className="mx-auto text-blue-600 dark:text-blue-400" />
          <p className="text-xs mt-1 font-medium truncate" title={getIpRole(clientIp)}>{getIpRole(clientIp)}</p>
        </div>
        <div className="w-1/3" /> {/* Spacer */}
        <div className="text-center w-1/3">
          <ServerIcon size={32} className="mx-auto text-green-600 dark:text-green-400" />
          <p className="text-xs mt-1 font-medium truncate" title={getIpRole(serverIp)}>{getIpRole(serverIp)}</p>
        </div>
      </div>

      {/* Flow Packets */}
      <div className="space-y-2 w-full text-xs">
        <div className={`flex items-center transition-opacity duration-500 ${step >= 1 ? 'opacity-100' : 'opacity-0'}`}>
          <span className="w-1/3 text-right pr-2">SYN</span>
          <ArrowRight size={16} className="text-slate-400 w-1/3 justify-center flex" />
          <span className="w-1/3"></span>
        </div>
        <div className={`flex items-center transition-opacity duration-500 ${step >= 2 ? 'opacity-100' : 'opacity-0'}`}>
          <span className="w-1/3"></span>
          <ArrowRight size={16} className="text-slate-400 w-1/3 justify-center flex transform rotate-180" />
          <span className="w-1/3 text-left pl-2">SYN-ACK</span>
        </div>
        <div className={`flex items-center transition-opacity duration-500 ${step >= 3 ? 'opacity-100' : 'opacity-0'}`}>
          <span className="w-1/3 text-right pr-2">ACK</span>
          <ArrowRight size={16} className="text-slate-400 w-1/3 justify-center flex" />
          <span className="w-1/3"></span>
        </div>
         {/* Opsional: Data exchange */}
        <div className={`flex items-center transition-opacity duration-500 ${step >= 4 ? 'opacity-100' : 'opacity-0'}`}>
          <span className="w-1/3 text-right pr-2 text-muted-foreground">Data...</span>
           <ArrowRight size={16} className="text-slate-300 w-1/3 justify-center flex transform rotate-180" />
          <span className="w-1/3 text-left pl-2 text-muted-foreground">...Data</span>
        </div>

        {/* RST Packet */}
        <div className={`flex items-center font-semibold transition-opacity duration-500 ${step >= 5 ? 'opacity-100' : 'opacity-0'}`}>
          <span className={`w-1/3 text-right pr-2 ${isResetFromClient ? 'text-red-500' : ''}`}>{isResetFromClient ? "RST" : ""}</span>
           {isResetFromClient ? 
            <ArrowRight size={18} className="text-red-500 w-1/3 justify-center flex" /> :
            <ArrowRight size={18} className="text-red-500 w-1/3 justify-center flex transform rotate-180" />
           }
          <span className={`w-1/3 text-left pl-2 ${!isResetFromClient ? 'text-red-500' : ''}`}>{!isResetFromClient ? "RST" : ""}</span>
        </div>
      </div>
      
      {step >= 5 && (
        <div className="mt-3 p-2 bg-red-100 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-md text-center">
            <XCircleIcon className="w-5 h-5 text-red-500 inline-block mr-1" />
            <span className="text-xs text-red-700 dark:text-red-300 font-medium">
                Connection Reset by: {resetInitiatorIp || "Unknown"}
            </span>
        </div>
      )}
      {step < 5 && <div className="h-[46px]"></div>} {/* Placeholder to prevent layout shift */}

      <Button variant="ghost" size="sm" onClick={() => setStep(0)} disabled={step < 5} className={`mt-auto text-xs ${step < 5 ? 'invisible' : ''}`}>
        <RefreshCw className="mr-1 h-3 w-3" /> Replay Animation
      </Button>
    </div>
  );
};


export function AIInsights({ analysisId, initialData: initialServerData, error: initialError }: AiInsightsProps) {
  const [data, setData] = useState<AiInsightsData | null>(initialServerData || null);
  const [isLoading, setIsLoading] = useState<boolean>(!initialServerData && !initialError);
  const [error, setError] = useState<string | null>(initialError || null);
  const [activePieIndex, setActivePieIndex] = useState<number>(0);
  const [analystNotes, setAnalystNotes] = useState<string>(initialServerData?.analystNotes || "");
  const [isSavingNotes, setIsSavingNotes] = useState<boolean>(false);
  // const [showRawPayloadModal, setShowRawPayloadModal] = useState<boolean>(false); // Jika masih digunakan
  // const [selectedPayload, setSelectedPayload] = useState<string | undefined>(undefined); // Jika masih digunakan
  const [currentTab, setCurrentTab] = useState<string>("summary");

  const [animationModalOpen, setAnimationModalOpen] = useState<boolean>(false); //
  const [animationData, setAnimationData] = useState<{ //
    type: string;
    sourceIp?: string;
    destinationIp?: string;
    packetNo?: number;
    packetInfo?: string;
    resetInitiatorIp?: string; 
  } | null>(null);

  const fetchData = useCallback(async (isRetry = false) => { /* ... (sama) ... */ if(!isRetry)setIsLoading(true);setError(null);console.log(`[AI_INSIGHTS] Fetching AI analysis data for ID: ${analysisId}`);try{const response=await fetch("/api/analyze-pcap",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({analysisId:analysisId}),});const result=await response.json();if(!response.ok)throw new Error(result.error||result.message||`HTTP error! status: ${response.status}`);if(result&&result.success&&result.analysis){const analysisData=result.analysis;setData(prevData=>({fileName:prevData?.fileName||analysisData.fileName||initialServerData?.fileName,fileSize:prevData?.fileSize||analysisData.fileSize||initialServerData?.fileSize,uploadDate:prevData?.uploadDate||analysisData.uploadDate||initialServerData?.uploadDate,...analysisData,status:"Completed",analystNotes:analysisData.analystNotes||prevData?.analystNotes||initialServerData?.analystNotes||"",samplePacketsForContext: analysisData.samplePacketsForContext || prevData?.samplePacketsForContext || initialServerData?.samplePacketsForContext || []}));setAnalystNotes(analysisData.analystNotes||data?.analystNotes||initialServerData?.analystNotes||"");}else{throw new Error(result.error||"Received unexpected data structure from AI analysis API.");}}catch(err:any){console.error("[AI_INSIGHTS] Error in fetchData:",err);setError(err.message||"An unknown error occurred while fetching AI analysis.");setData(prevData=>({...prevData,status:"Error"}as AiInsightsData));}finally{setIsLoading(false);}}, [analysisId, data?.analystNotes, initialServerData]);

  useEffect(() => { /* ... (sama) ... */ if(initialServerData&&!initialError){setData(initialServerData);setAnalystNotes(initialServerData.analystNotes||"");setIsLoading(false);}else if(initialError){setError(initialError);setIsLoading(false);}else if(!data&&analysisId&&isLoading){fetchData();}else if(data&&!isLoading){/* Data already loaded or no fetch needed initially */}}, [analysisId, initialServerData, initialError, data, isLoading, fetchData]);

  const onPieEnter = useCallback((_: any, index: number) => setActivePieIndex(index), []);
  const handleSaveNotes = async () => { /* ... (sama) ... */ setIsSavingNotes(true);setError(null);try{const response=await fetch(`/api/analysis/${analysisId}/notes`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({notes:analystNotes}),});if(!response.ok){const errorData=await response.json().catch(()=>({message:"Failed to save notes"}));throw new Error(errorData.message||"Failed to save notes");}const saveData=await response.json();console.log("Notes saved successfully:",saveData);setData(prevData=>prevData?{...prevData,analystNotes:analystNotes}:null);alert("Notes saved!");}catch(err:any){console.error("Error saving notes:",err);setError(`Failed to save notes: ${err.message}`);}finally{setIsSavingNotes(false);}};
  const handleExport = (format: 'json' | 'txt' | 'csv_alerts' | 'csv_conversations') => { /* ... (sama) ... */ if(!data){alert("No data available to export.");return;}let content="";let fileName=`analysis_${analysisId}_${data.fileName||"export"}`;let contentType="text/plain";try{switch(format){case"json":content=JSON.stringify(data,null,2);fileName+=".json";contentType="application/json";break;case"txt":content=`Analysis Report for: ${data.fileName||"N/A"}\n`;content+=`File Size: ${data.fileSize||"N/A"}\n`;content+=`Upload Date: ${data.uploadDate?new Date(data.uploadDate).toLocaleString():"N/A"}\n\n`;content+=`Summary:\n${data.summary||"N/A"}\n\n`;content+=`Threat Analysis:\n${data.threatAnalysis||"N/A"}\n\n`;if(data.iocs&&data.iocs.length>0){content+="IOCs:\n";data.iocs.forEach(ioc=>{content+=`- Type: ${ioc.type}, Value: ${ioc.value}, Context: ${ioc.context}, Confidence: ${ioc.confidence}%\n`;});content+="\n";}content+="Recommendations:\n";if(Array.isArray(data.recommendations)){data.recommendations.forEach(rec=>{content+=`- ${rec.title||"Recommendation"}: ${rec.description||""} (Priority: ${rec.priority||"N/A"})\n`;});}else if(typeof data.recommendations==="string"){content+=data.recommendations;}else{content+="N/A";}fileName+=".txt";contentType="text/plain";break;}const blob=new Blob([content],{type:contentType});const link=document.createElement("a");link.href=URL.createObjectURL(blob);link.download=fileName;document.body.appendChild(link);link.click();document.body.removeChild(link);URL.revokeObjectURL(link.href);}catch(exportError:any){alert(`Failed to export data: ${exportError.message}`);}};
  const handleShare = () => { /* ... (sama) ... */ if(navigator.share){navigator.share({title:`PCAP Analysis: ${data?.fileName||analysisId}`,text:`Check out the AI-driven analysis for this PCAP file: ${data?.summary||"No summary available."}`,url:window.location.href,}).then(()=>console.log("Successful share")).catch((error)=>console.log("Error sharing",error));}else{navigator.clipboard.writeText(window.location.href).then(()=>alert("Link copied to clipboard!")).catch(()=>alert("Could not copy link."));}};
  const handlePrint = () => { window.print(); };

  const handleVisualizeError = (errorDetail: ErrorAnalysisDetail) => { //
    if (!data?.samplePacketsForContext || !errorDetail.relatedPacketSamples || errorDetail.relatedPacketSamples.length === 0) {
      alert("No related packet samples available to visualize this error.");
      return;
    }
    const firstPacketNo = errorDetail.relatedPacketSamples[0];
    const relatedPacket = data.samplePacketsForContext.find(p => p.no === firstPacketNo);

    if (!relatedPacket) {
      alert(`Details for packet sample #${firstPacketNo} not found in context data.`);
      return;
    }
    
    setAnimationData({
      type: errorDetail.errorType,
      sourceIp: relatedPacket.source, // IP yang mengirim paket sampel ini
      destinationIp: relatedPacket.destination, // IP tujuan paket sampel ini
      packetNo: relatedPacket.no,
      packetInfo: relatedPacket.info,
      resetInitiatorIp: relatedPacket.source // Asumsikan source dari paket sampel RST adalah pengirim RST
    });
    setAnimationModalOpen(true);
  };


  if (isLoading && !data) { /* ... (Loading UI sama) ... */ return(<div className="flex flex-col items-center justify-center min-h-[300px] p-4"><div className="text-center"><Loader2 className="w-12 h-12 text-blue-500 animate-spin mx-auto mb-4"/><h2 className="text-xl font-semibold mb-2">Loading AI Insights...</h2><p className="text-gray-600 dark:text-gray-300 mb-4">The AI is analyzing your PCAP data. This may take a few moments.</p><Progress value={30}className="w-full max-w-md mx-auto"/><p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Analysis ID: {analysisId}</p></div></div>); }
  if (error && !isLoading && (!data || data.status === 'Error')) { /* ... (Error UI sama) ... */ return(<Alert variant="destructive"className="max-w-2xl mx-auto my-8"><AlertCircle className="h-4 w-4"/><AlertTitle>Error Fetching Analysis</AlertTitle><AlertDescription><p>{error}</p><p>Analysis ID: {analysisId}</p><Button onClick={()=>fetchData(true)}variant="outline"className="mt-4"disabled={isLoading}><RefreshCw className="mr-2 h-4 w-4"/>{isLoading?"Retrying...":"Try Again"}</Button></AlertDescription></Alert>); }
  if (!data && !isLoading) { /* ... (No Data UI sama) ... */ return(<Alert className="max-w-2xl mx-auto my-8"><Info className="h-4 w-4"/><AlertTitle>No AI Insights Available</AlertTitle><AlertDescription><p>AI insights could not be loaded for analysis ID: {analysisId}. The analysis might still be processing or an issue occurred.</p><Button onClick={()=>fetchData(true)}variant="outline"className="mt-4"disabled={isLoading}><RefreshCw className="mr-2 h-4 w-4"/>{isLoading?"Refreshing...":"Refresh"}</Button></AlertDescription></Alert>); }
  
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
                <CardDescription className="text-xs md:text-sm text-gray-600 dark:text-gray-400 mt-1">ID: {analysisId}</CardDescription>
              </div>
              <div className="flex space-x-1 sm:space-x-2 self-start sm:self-center">
                <Tooltip><TooltipTrigger asChild><Button variant="outline" size="icon" onClick={() => handleExport('json')} className="h-8 w-8 sm:h-9 sm:w-9"><Download className="h-4 w-4" /><span className="sr-only">Export JSON</span></Button></TooltipTrigger><TooltipContent><p>Export Full Report (JSON)</p></TooltipContent></Tooltip>
                <Tooltip><TooltipTrigger asChild><Button variant="outline" size="icon" onClick={() => handleExport('txt')} className="h-8 w-8 sm:h-9 sm:w-9"><FileText className="h-4 w-4" /><span className="sr-only">Export TXT</span></Button></TooltipTrigger><TooltipContent><p>Export Summary (TXT)</p></TooltipContent></Tooltip>
                <Tooltip><TooltipTrigger asChild><Button variant="outline" size="icon" onClick={handleShare} className="h-8 w-8 sm:h-9 sm:w-9"><Share2 className="h-4 w-4" /><span className="sr-only">Share</span></Button></TooltipTrigger><TooltipContent><p>Share Analysis</p></TooltipContent></Tooltip>
                <Tooltip><TooltipTrigger asChild><Button variant="outline" size="icon" onClick={handlePrint} className="h-8 w-8 sm:h-9 sm:w-9"><Printer className="h-4 w-4" /><span className="sr-only">Print</span></Button></TooltipTrigger><TooltipContent><p>Print View</p></TooltipContent></Tooltip>
                <Tooltip><TooltipTrigger asChild><Button variant="ghost" size="icon" onClick={() => fetchData(true)} disabled={isLoading} className="h-8 w-8 sm:h-9 sm:w-9"><RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} /><span className="sr-only">Refresh Data</span></Button></TooltipTrigger><TooltipContent><p>Refresh Analysis Data</p></TooltipContent></Tooltip>
              </div>
            </div>
            <div className="mt-3 md:mt-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-x-4 gap-y-2 text-xs md:text-sm text-gray-500 dark:text-gray-400">
                <p><strong>File Size:</strong> {data.fileSize || "N/A"}</p>
                <p><strong>Uploaded:</strong> {data.uploadDate ? new Date(data.uploadDate).toLocaleString() : "N/A"}</p>
                <p><strong>Analysis Status:</strong> <Badge variant={getStatusVariant(data.status)}>{data.status || "UNKNOWN"}</Badge></p>
                <p><strong>Threat Level:</strong> <Badge variant={ data.threatLevel?.toLowerCase() === 'critical' || data.threatLevel?.toLowerCase() === 'high' ? 'destructive' : data.threatLevel?.toLowerCase() === 'medium' ? 'default' : 'outline' }>{data.threatLevel || "N/A"}</Badge></p>
            </div>
            {data.trafficBehaviorScore && (
              <div className="mt-3 md:mt-4 border-t dark:border-gray-700 pt-3">
                <h4 className="text-sm font-semibold mb-1 text-gray-700 dark:text-gray-300">Traffic Behavior Score:</h4>
                <div className="flex items-center gap-2">
                  <span className={`text-2xl font-bold ${ data.trafficBehaviorScore.score >= 75 ? 'text-red-600 dark:text-red-400' : data.trafficBehaviorScore.score >= 50 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400' }`}> {data.trafficBehaviorScore.score}/100 </span>
                  <Tooltip><TooltipTrigger asChild><Info className="h-4 w-4 text-muted-foreground cursor-help" /></TooltipTrigger><TooltipContent side="top" className="max-w-xs bg-slate-800 text-white p-2 rounded shadow-lg text-xs"><p>{data.trafficBehaviorScore.justification}</p></TooltipContent></Tooltip>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{data.trafficBehaviorScore.justification}</p>
              </div>
            )}
          </CardHeader>

          <CardContent className="pt-4 md:pt-6">
            <Tabs value={currentTab} onValueChange={setCurrentTab} className="w-full">
              <ScrollArea className="w-full whitespace-nowrap rounded-md border-b dark:border-gray-700">
                <TabsList className="mb-0 flex-nowrap px-1 -mx-1">
                  <TabsTrigger value="summary" className="flex items-center text-xs sm:text-sm"><Info className="mr-1 sm:mr-2 h-4 w-4" />Summary</TabsTrigger>
                  <TabsTrigger value="errors_threats" className="flex items-center text-xs sm:text-sm"><Siren className="mr-1 sm:mr-2 h-4 w-4" />Errors & Threats</TabsTrigger>
                  <TabsTrigger value="recommendations" className="flex items-center text-xs sm:text-sm"><MessageSquare className="mr-1 sm:mr-2 h-4 w-4" />Actions</TabsTrigger>
                  <TabsTrigger value="timeline" className="flex items-center text-xs sm:text-sm"><Clock className="mr-1 sm:mr-2 h-4 w-4" />Timeline</TabsTrigger>
                  <TabsTrigger value="visuals" className="flex items-center text-xs sm:text-sm"><BarChart2 className="mr-1 sm:mr-2 h-4 w-4" />Visuals</TabsTrigger>
                  {data.performanceMetrics && <TabsTrigger value="performance" className="flex items-center text-xs sm:text-sm"><Activity className="mr-1 sm:mr-2 h-4 w-4" />Perf.</TabsTrigger>}
                </TabsList>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>

              <div className="mt-4 md:mt-6">
                <TabsContent value="summary">
                  <Card><CardHeader><CardTitle className="flex items-center text-lg"><Info className="mr-2 text-blue-500"/>Overall Summary</CardTitle></CardHeader><CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base"><p>{data.summary||"No summary provided by AI."}</p></CardContent></Card>
                </TabsContent>

                <TabsContent value="errors_threats">
                  <div className="space-y-6">
                    {data.errorAnalysisReport && data.errorAnalysisReport.length > 0 ? (
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center text-lg">
                            <AlertTriangle className="mr-2 text-orange-500" /> Detailed Error Analysis
                          </CardTitle>
                          <CardDescription>AI-generated insights into detected packet errors and anomalies.</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <Accordion type="multiple" className="w-full">
                            {data.errorAnalysisReport.map((errorDetail, index) => (
                              <AccordionItem value={`error-${index}`} key={`error-${index}`}>
                                <AccordionTrigger className="hover:no-underline text-sm md:text-base">
                                  <div className="flex items-center justify-between w-full">
                                    <span className="font-semibold">{errorDetail.errorType}</span>
                                    <Badge variant="destructive" className="text-xs">{errorDetail.count} occurrences</Badge>
                                  </div>
                                </AccordionTrigger>
                                <AccordionContent className="pt-2 pb-4 px-1 space-y-3 text-sm">
                                  <p><strong>Description:</strong> {errorDetail.description}</p>
                                  <div>
                                    <h4 className="font-semibold mb-1">Possible Causes:</h4>
                                    <ul className="list-disc pl-5 space-y-0.5 text-xs">
                                      {errorDetail.possibleCauses.map((cause, i) => <li key={i}>{cause}</li>)}
                                    </ul>
                                  </div>
                                  <div>
                                    <h4 className="font-semibold mb-1">Troubleshooting Suggestions:</h4>
                                    <ul className="list-disc pl-5 space-y-0.5 text-xs">
                                      {errorDetail.troubleshootingSuggestions.map((suggestion, i) => <li key={i}>{suggestion}</li>)}
                                    </ul>
                                  </div>
                                  {errorDetail.relatedPacketSamples && errorDetail.relatedPacketSamples.length > 0 && (
                                    <p className="text-xs text-muted-foreground">
                                      Related sample packet numbers: {errorDetail.relatedPacketSamples.join(', ')}
                                    </p>
                                  )}
                                  {/* Tombol Visualize */}
                                  {(errorDetail.errorType.toLowerCase().includes("tcp reset") || errorDetail.errorType.toLowerCase().includes("reset")) && 
                                   errorDetail.relatedPacketSamples && errorDetail.relatedPacketSamples.length > 0 && (
                                    <div className="mt-3 pt-3 border-t dark:border-gray-700">
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => handleVisualizeError(errorDetail)}
                                        className="text-xs"
                                      >
                                        <Zap className="mr-1.5 h-3.5 w-3.5" /> Visualize Flow
                                      </Button>
                                    </div>
                                  )}
                                </AccordionContent>
                              </AccordionItem>
                            ))}
                          </Accordion>
                        </CardContent>
                      </Card>
                    ) : (
                      <Card>
                        <CardHeader><CardTitle className="flex items-center text-lg"><AlertTriangle className="mr-2 text-orange-500" /> Detailed Error Analysis</CardTitle></CardHeader>
                        <CardContent><p className="text-sm text-muted-foreground">No specific error analysis provided by AI, or no significant errors detected in the sample packets.</p></CardContent>
                      </Card>
                    )}

                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center text-lg">
                                <Shield className="mr-2 text-red-500" /> General Threat Intelligence & IOCs
                                {data.threatLevel && ( <Badge variant={ data.threatLevel.toLowerCase() === 'critical' || data.threatLevel.toLowerCase() === 'high' ? 'destructive' : data.threatLevel.toLowerCase() === 'medium' ? 'default' : 'outline' } className="ml-3 text-xs"> Threat Level: {data.threatLevel} </Badge> )}
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div> <h3 className="font-semibold mb-2 text-base">Threat Analysis Summary:</h3> <p className="prose dark:prose-invert max-w-none text-sm md:text-base">{data.threatAnalysis || "No general threat analysis provided by AI."}</p> </div>
                            {data.findings && data.findings.length > 0 && ( <div> <h3 className="font-semibold mt-4 mb-2 text-base">Specific Security Findings:</h3> <Accordion type="single" collapsible className="w-full"> {data.findings.map((finding,idx) => ( <AccordionItem value={finding.id || `finding-${idx}`} key={finding.id || `finding-${idx}`}> <AccordionTrigger className="text-sm hover:no-underline text-left">{finding.title || "Untitled Finding"} <Badge variant="outline" className="ml-2 text-xs">{finding.severity || 'N/A'}</Badge></AccordionTrigger> <AccordionContent className="text-xs space-y-1 pl-4"> <p><strong>Description:</strong> {finding.description}</p> <p><strong>Recommendation:</strong> {finding.recommendation}</p> <p><strong>Category:</strong> {finding.category}</p> {finding.affectedHosts && finding.affectedHosts.length > 0 && <p><strong>Affected Hosts:</strong> {finding.affectedHosts.join(', ')}</p>} {finding.relatedPackets && finding.relatedPackets.length > 0 && <p><strong>Related Packet Samples (No.):</strong> {finding.relatedPackets.join(', ')}</p>} <p><strong>Confidence:</strong> {finding.confidence !== undefined ? `${finding.confidence}%` : 'N/A'}</p> </AccordionContent> </AccordionItem> ))} </Accordion> </div> )}
                            {data.iocs && data.iocs.length > 0 ? ( <div className="mt-6"> <IOCList iocs={data.iocs} /> </div> ) : ( <div className="mt-6"> <h3 className="font-semibold mb-2 text-base">Indicators of Compromise (IOCs):</h3> <p className="text-sm text-muted-foreground">No specific IOCs were identified by the AI in this analysis.</p> </div> )}
                        </CardContent>
                    </Card>
                  </div>
                </TabsContent>
                {/* ... (Konten Tab lainnya tetap sama) ... */}
                <TabsContent value="recommendations"><Card><CardHeader><CardTitle className="flex items-center text-lg"><MessageSquare className="mr-2 text-green-500"/>Recommended Actions</CardTitle></CardHeader><CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base">{data.recommendations&&Array.isArray(data.recommendations)&&data.recommendations.length>0?(<ul className="list-disc pl-5 space-y-2">{data.recommendations.map((rec,index)=>(<li key={index}><strong className="font-medium">{rec.title||`Recommendation ${index+1}`}</strong> (Priority: {rec.priority||"N/A"}):<p className="text-sm ml-4">{rec.description||"No detailed description."}</p></li>))}</ul>):(<p>{typeof data.recommendations==="string"?data.recommendations:"No specific recommendations provided by AI."}</p>)}</CardContent></Card></TabsContent>
                <TabsContent value="timeline"><Card><CardHeader><CardTitle className="flex items-center text-lg"><Clock className="mr-2 text-fuchsia-500"/>Event Timeline</CardTitle></CardHeader><CardContent>{data.timeline&&data.timeline.length>0?(<div className="relative pl-6 space-y-6 border-l-2 border-gray-200 dark:border-gray-700">{data.timeline.map((event,index)=>(<div key={index}className="relative"><div className={`absolute -left-[calc(0.75rem+1px)] mt-1.5 flex h-6 w-6 items-center justify-center rounded-full ${event.severity==="error"?"bg-red-500":event.severity==="warning"?"bg-yellow-500":"bg-blue-500"} text-white text-xs font-semibold`}>{event.severity==="error"?<AlertCircle size={14}/>:event.severity==="warning"?<AlertTriangle size={14}/>:<Info size={14}/>}</div><div className="ml-4"><p className="font-medium text-sm">{event.event||"Unknown Event"}</p><p className="text-xs text-muted-foreground">{event.time&&!event.time.includes("Packet Sample")?new Date(event.time).toLocaleString():event.time||"N/A"}</p></div></div>))}</div>):(<p className="text-center text-gray-500 dark:text-gray-400 py-4">No timeline events provided by AI.</p>)}</CardContent></Card></TabsContent>
                <TabsContent value="visuals"className="space-y-6">{data.protocolDistribution&&data.protocolDistribution.length>0&&(<Card><CardHeader><CardTitle className="flex items-center text-lg"><PieChartIcon className="mr-2 text-purple-500"/>Protocol Distribution</CardTitle></CardHeader><CardContent style={{width:"100%",height:300}}><ResponsiveContainer><PieChart><Pie activeIndex={activePieIndex}activeShape={renderActiveShape}data={data.protocolDistribution}cx="50%"cy="50%"innerRadius={60}outerRadius={100}fill="#8884d8"dataKey="value"onMouseEnter={onPieEnter}>{data.protocolDistribution.map((entry,index)=>(<Cell key={`cell-${index}`}fill={entry.fill||COLORS[index%COLORS.length]}/>))}</Pie><RechartsTooltip/><Legend layout="vertical"align="right"verticalAlign="middle"iconSize={10}wrapperStyle={{fontSize:"12px"}}/></PieChart></ResponsiveContainer></CardContent></Card>)} {data.statistics?.topTalkers&&data.statistics.topTalkers.length>0&&data.statistics.topTalkers[0].ip!=="No identifiable IP traffic"&&(<Card><CardHeader><CardTitle className="flex items-center text-lg"><BarChart2 className="mr-2 text-green-500"/>Top Talkers (by Packets)</CardTitle></CardHeader><CardContent style={{width:"100%",height:300}}><ResponsiveContainer><BarChart data={data.statistics.topTalkers}layout="vertical"margin={{top:5,right:30,left:20,bottom:5}}><CartesianGrid strokeDasharray="3 3"/><XAxis type="number"/><YAxis dataKey="ip"type="category"width={150}interval={0}tick={{fontSize:10}}/><RechartsTooltip/><Legend wrapperStyle={{fontSize:"12px"}}/><Bar dataKey="packets"name="Total Packets"fill="#82ca9d"/></BarChart></ResponsiveContainer></CardContent></Card>)}</TabsContent>
                {data.performanceMetrics&&(<TabsContent value="performance"><Card><CardHeader><CardTitle className="flex items-center text-lg"><Activity className="mr-2 text-cyan-500"/>Performance</CardTitle></CardHeader><CardContent className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-sm md:text-base"><div><strong>Total Packets (in file):</strong> {data.performanceMetrics.totalPackets?.toLocaleString()||data.statistics?.totalPacketsInFile?.toLocaleString()||"N/A"}</div><div><strong>Total Bytes (in file):</strong> {data.performanceMetrics.totalBytes?.toLocaleString()||data.statistics?.totalBytesInFile?.toLocaleString()||"N/A"}</div><div><strong>Capture Duration:</strong> {data.performanceMetrics.captureDuration||"N/A"}</div><div><strong>Avg Packet Rate:</strong> {data.performanceMetrics.averagePacketRate||"N/A"}</div></CardContent></Card></TabsContent>)}

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
            <Textarea value={analystNotes} onChange={(e) => setAnalystNotes(e.target.value)} placeholder="Type your notes here..." rows={5} className="mb-3 text-sm md:text-base" />
            <Button onClick={handleSaveNotes} disabled={isSavingNotes} size="sm">
              {isSavingNotes ? (<><Loader2 className="mr-2 h-4 w-4 animate-spin"/>Saving...</>) : "Save Notes"}
            </Button>
          </CardContent>
        </Card>

        {/* Modal untuk Animasi */}
        {animationModalOpen && animationData && ( //
          <Dialog open={animationModalOpen} onOpenChange={setAnimationModalOpen}>
            <DialogContent className="sm:max-w-lg md:max-w-xl lg:max-w-2xl">
              <DialogHeader>
                <DialogTitle className="flex items-center">
                  <Zap className="mr-2 h-5 w-5 text-yellow-500" /> 
                  Error Flow: {animationData.type}
                </DialogTitle>
                <DialogDescription>
                  Visualizing packet interaction for: {animationData.type}. 
                  {animationData.packetNo && ` (Context from sample packet #${animationData.packetNo})`}
                </DialogDescription>
              </DialogHeader>
              
              {animationData.type === "TCP Reset" && ( //
                <TcpResetAnimation 
                  clientIp={animationData.sourceIp} // Asumsi sourceIp adalah client dalam konteks ini
                  serverIp={animationData.destinationIp} // Asumsi destinationIp adalah server
                  resetInitiatorIp={animationData.resetInitiatorIp}
                  packetInfo={animationData.packetInfo}
                />
              )}
              {/* Anda bisa menambahkan kondisi lain untuk tipe animasi error berbeda */}
              {/* else if (animationData.type === "SomeOtherError") { <SomeOtherAnimation ... /> } */}

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
