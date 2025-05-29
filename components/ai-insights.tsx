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
  Server as ServerIcon, User as UserIcon, ArrowRight, XCircle as XCircleIcon, Zap, Mail,
  ArrowLeftRight, Send, PhoneOff, ArrowLeft // Tambahkan ArrowLeft
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
interface ProtocolDistribution { name: string; value: number; fill: string; }
interface Conversation { id: string; sourceIp: string; destinationIp: string; protocol: string; packets: number; bytes: number; startTime?: string; endTime?: string; duration?: string; }
interface AlertInfo { id: string; timestamp: string; severity: 'Low' | 'Medium' | 'High' | 'Critical'; description: string; sourceIp?: string; destinationIp?: string; protocol?: string; signature?: string; }
interface DetailedPacketInfo { id: string; timestamp: string; source: string; destination: string; protocol: string; length: number; summary: string; payload?: string; }
interface IOC { type: "ip" | "domain" | "url" | "hash"; value: string; context: string; confidence: number; }
interface ErrorAnalysisDetail { errorType: string; count: number; description: string; possibleCauses: string[]; troubleshootingSuggestions: string[]; relatedPacketSamples?: number[]; }
interface SamplePacketForContext { no: number; timestamp: string; source: string; destination: string; protocol: string; length: number; info: string; isError?: boolean; errorType?: string; }

interface VoipCallAnalysis {
  callId?: string;
  caller?: string;
  callee?: string;
  status: 'Completed' | 'Failed' | 'Attempting' | 'No Answer' | 'Busy' | 'Ringing' | 'InProgress';
  failureReason?: string;
  relatedPackets?: number[];
  duration?: string;
  startTime?: string;
  protocol?: 'SIP' | 'SCCP' | 'H323' | 'RTP' | 'RTCP' | 'Unknown';
  qualityMetrics?: { jitter?: string; packetLoss?: string; mos?: number };
}
interface VoipAnalysisReport {
  summary?: string;
  detectedCalls?: VoipCallAnalysis[];
  potentialIssues?: Array<{
    issueType: string; 
    description: string;
    evidence?: string; 
    recommendation?: string;
    severity?: 'Low' | 'Medium' | 'High';
  }>;
  cucmSpecificAnalysis?: {
    registrationIssues?: string[];
    callProcessingErrors?: string[];
    commonCUCMProblems?: string;
  };
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
  performanceMetrics?: { totalPackets: number; totalBytes: number; captureDuration: string; averagePacketRate: string; };
  geoIpInformation?: { sourceIp: string; destinationIp: string; sourceLocation?: string; destinationLocation?: string; }[];
  attackPatterns?: { patternName: string; description: string; involvedIps: string[]; }[];
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
  findings?: Array<{ id?: string; title?: string; description?: string; severity?: string; confidence?: number; recommendation?: string; category?: string; affectedHosts?: string[]; relatedPacketSamples?: number[]; }>;
  iocs?: IOC[];
  statistics?: any;
  timeline?: Array<{ time?: string; event?: string; severity?: string; }>;
  trafficBehaviorScore?: { score: number; justification: string; };
  errorAnalysisReport?: ErrorAnalysisDetail[];
  samplePacketsForContext?: SamplePacketForContext[];
  voipAnalysisReport?: VoipAnalysisReport; 
}

interface AiInsightsProps {
  analysisId: string;
  initialData?: AiInsightsData | null;
  error?: string | null;
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82Ca9D', '#FF7F50', '#DC143C'];
const getStatusVariant = (status?: string): "default" | "secondary" | "destructive" | "outline" => { switch(status?.toLowerCase()){case"completed":return"default";case"processing":case"pending":return"secondary";case"error":return"destructive";default:return"outline"}};
const renderActiveShape = (props: any) => { const RADIAN=Math.PI/180;const{cx,cy,midAngle,innerRadius,outerRadius,startAngle,endAngle,fill,payload,percent,value}=props;const sin=Math.sin(-RADIAN*midAngle);const cos=Math.cos(-RADIAN*midAngle);const sx=cx+(outerRadius+10)*cos;const sy=cy+(outerRadius+10)*sin;const mx=cx+(outerRadius+30)*cos;const my=cy+(outerRadius+30)*sin;const ex=mx+(cos>=0?1:-1)*22;const ey=my;const textAnchor=cos>=0?"start":"end";return(<g><text x={cx}y={cy}dy={8}textAnchor="middle"fill={fill}>{payload.name}</text><Sector cx={cx}cy={cy}innerRadius={innerRadius}outerRadius={outerRadius}startAngle={startAngle}endAngle={endAngle}fill={fill}/><Sector cx={cx}cy={cy}startAngle={startAngle}endAngle={endAngle}innerRadius={outerRadius+6}outerRadius={outerRadius+10}fill={fill}/><path d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`}stroke={fill}fill="none"/><circle cx={ex}cy={ey}r={2}fill={fill}stroke="none"/><text x={ex+(cos>=0?1:-1)*12}y={ey}textAnchor={textAnchor}fill="#333">{`${value}`}</text><text x={ex+(cos>=0?1:-1)*12}y={ey}dy={18}textAnchor={textAnchor}fill="#999">{`(Rate ${(percent*100).toFixed(2)}%)`}</text></g>)};

// --- Komponen Animasi TCP Reset ---
interface TcpResetAnimationProps {
  clientIp?: string;
  serverIp?: string;
  resetInitiatorIp?: string;
  packetInfo?: string;
  errorType?: string;
}

const TcpResetAnimation: React.FC<TcpResetAnimationProps> = ({ clientIp = "Client", serverIp = "Server", resetInitiatorIp, packetInfo, errorType }) => {
  const [currentStep, setCurrentStep] = useState(0); 
  const [showStepLabel, setShowStepLabel] = useState(false);

  const animationSteps = React.useMemo(() => [ 
    { name: "SYN", from: clientIp, to: serverIp, color: "blue-500", description: `${clientIp} mengirim SYN (Synchronization) ke ${serverIp} untuk memulai koneksi.` },
    { name: "SYN-ACK", from: serverIp, to: clientIp, color: "green-500", description: `${serverIp} merespons dengan SYN-ACK (Synchronization-Acknowledgement) ke ${clientIp}.` },
    { name: "ACK", from: clientIp, to: serverIp, color: "blue-500", description: `${clientIp} mengirim ACK (Acknowledgement). Koneksi TCP berhasil terbentuk.` },
    { name: "RST", from: resetInitiatorIp, to: (resetInitiatorIp === clientIp ? serverIp : clientIp), color: "red-500", isReset: true, description: `Paket RST (Reset) dikirim dari ${resetInitiatorIp || 'salah satu pihak'}, mengindikasikan koneksi dihentikan secara paksa.` },
  ], [clientIp, serverIp, resetInitiatorIp]);
  
  const stepDuration = 3000; // Durasi per langkah animasi (ms) - lebih lambat lagi
  const labelDelay = 500; // Delay sebelum label deskripsi muncul

  useEffect(() => {
    let timeouts: NodeJS.Timeout[] = [];
    if (currentStep === 0) { // Hanya trigger sequence jika currentStep adalah 0 (awal atau setelah replay)
      setShowStepLabel(false);

      // Mulai langkah pertama setelah sedikit delay untuk memastikan UI siap
      timeouts.push(setTimeout(() => {
        setCurrentStep(1); // Pindah ke langkah pertama
        timeouts.push(setTimeout(() => setShowStepLabel(true), labelDelay));
      }, 100)); // Delay awal yang sangat kecil

      // Jadwalkan langkah-langkah berikutnya
      for (let i = 1; i < animationSteps.length; i++) {
        timeouts.push(
          setTimeout(() => {
            setCurrentStep(i + 1); // Pindah ke langkah i+1 (jadi 2, 3, 4)
            setShowStepLabel(false); // Sembunyikan label lama
            timeouts.push(setTimeout(() => setShowStepLabel(true), labelDelay)); // Tampilkan label baru setelah delay
          }, (i * stepDuration) + 100) // Waktu relatif terhadap awal replay
        );
      }

      // Jadwalkan status akhir (setelah semua langkah animasi)
      timeouts.push(
        setTimeout(() => {
          setCurrentStep(animationSteps.length + 1); // Status "selesai"
          setShowStepLabel(true); // Tampilkan pesan akhir (pesan reset)
        }, (animationSteps.length * stepDuration) + 500) 
      );
    }

    return () => { // Cleanup function
      timeouts.forEach(clearTimeout);
    };
  }, [currentStep, animationSteps, stepDuration, labelDelay]); // Re-run jika currentStep atau definisi steps berubah

  const getIpRole = (ip: string, isInitiator: boolean, isClient: boolean) => {
    let role = isClient ? "Klien" : "Server";
    if (isInitiator) role += " (Pengirim RST)";
    return `${ip} (${role})`;
  }

  const currentStepDetails = currentStep > 0 && currentStep <= animationSteps.length ? animationSteps[currentStep - 1] : null;

  return (
    <div className="p-6 space-y-4 min-h-[480px] flex flex-col items-center justify-between bg-slate-100 dark:bg-slate-800/70 rounded-xl border-2 border-slate-200 dark:border-slate-700 shadow-xl relative overflow-hidden">
      <div>
        <p className="text-xl font-bold text-center text-foreground mb-1.5">
          {errorType || "TCP Reset Flow"}
        </p>
        {packetInfo && <p className="text-xs text-center text-muted-foreground mb-4 max-w-md">Konteks Paket Terkait: {packetInfo}</p>}
      </div>
      
      <div className="flex justify-around w-full items-center mb-8 px-4">
        <div className="text-center w-2/5 flex flex-col items-center">
          <UserIcon size={52} className="text-blue-600 dark:text-blue-400 mb-2 p-2 bg-blue-100 dark:bg-blue-900/50 rounded-full shadow-md" />
          <p className="text-sm font-semibold truncate max-w-full" title={getIpRole(clientIp, clientIp === resetInitiatorIp, true)}>{clientIp}</p>
          <p className="text-xs text-muted-foreground">(Klien{clientIp === resetInitiatorIp ? ", Pengirim RST" : ""})</p>
        </div>
        <div className="w-1/5 flex justify-center items-center">
            <ArrowLeftRight size={36} className="text-slate-400 dark:text-slate-500 opacity-80" />
        </div> 
        <div className="text-center w-2/5 flex flex-col items-center">
          <ServerIcon size={52} className="text-green-600 dark:text-green-400 mb-2 p-2 bg-green-100 dark:bg-green-900/50 rounded-full shadow-md" />
          <p className="text-sm font-semibold truncate max-w-full" title={getIpRole(serverIp, serverIp === resetInitiatorIp, false)}>{serverIp}</p>
          <p className="text-xs text-muted-foreground">(Server{serverIp === resetInitiatorIp ? ", Pengirim RST" : ""})</p>
        </div>
      </div>

      {/* Animated Packets Area */}
      <div className="w-full h-40 relative mb-4 border-y-2 border-dashed border-slate-300 dark:border-slate-700 flex flex-col justify-around overflow-hidden">
        {animationSteps.map((step, index) => {
          const isActive = currentStep === index + 1;
          const isFromClient = step.from === clientIp;
          const packetBaseColor = step.isReset ? "text-red-600 dark:text-red-400" : step.color === "blue-500" ? "text-blue-600 dark:text-blue-400" : "text-green-600 dark:text-green-400";
          const packetBgColor = step.isReset ? "bg-red-600" : step.color === "blue-500" ? "bg-blue-600" : "bg-green-600";
          
          return (
            <div
              key={index}
              className={`absolute top-1/2 -translate-y-1/2 w-auto flex items-center transition-all duration-1000 ease-in-out
                          ${isActive ? 'opacity-100 z-10' : 'opacity-0 -z-10'}
                          ${isActive && isFromClient ? 'animate-packet-move-right-detailed-v3' : ''}
                          ${isActive && !isFromClient ? 'animate-packet-move-left-detailed-v3' : ''}
                        `}
            >
              <div className={`flex items-center py-2 px-3 rounded-lg shadow-2xl text-white text-base font-semibold ${packetBgColor}`}>
                <Send size={18} className="mr-2.5" /> 
                {step.name}
                {step.isReset && <XCircleIcon size={18} className="ml-2.5"/>}
              </div>
              {/* Keterangan source & dest pada paket */}
              {isActive && (
                <div className={`absolute -bottom-8 text-xs font-semibold ${packetBaseColor} ${isFromClient ? 'left-0 text-left' : 'right-0 text-right'} whitespace-nowrap w-full px-1`}>
                  {isFromClient ? 
                    <span className="flex items-center"><ArrowRight size={16} className="mr-1.5"/> {step.from} <span className="mx-1 text-slate-400 dark:text-slate-500">→</span> {step.to}</span> : 
                    <span className="flex items-center justify-end">{step.to} <span className="mx-1 text-slate-400 dark:text-slate-500">←</span> {step.from} <ArrowLeft size={16} className="ml-1.5"/></span>
                  }
                </div>
              )}
            </div>
          );
        })}
      </div>
      
      {/* Keterangan Tahap Animasi */}
      <div className="h-16 flex items-center justify-center text-center px-2">
        {currentStepDetails && showStepLabel && (
          <p className={`text-sm text-muted-foreground animate-fade-in-custom-v2`}>
            <span className={`font-bold ${currentStepDetails.isReset ? 'text-red-600 dark:text-red-400' : currentStepDetails.color === 'blue-500' ? 'text-blue-600 dark:text-blue-400' : 'text-green-600 dark:text-green-400'}`}>{currentStepDetails.name}</span>: {currentStepDetails.description}
          </p>
        )}
        {currentStep > animationSteps.length && showStepLabel && ( // Tampilkan ini hanya jika animasi selesai dan label harus muncul
             <div className="p-3 bg-red-100 dark:bg-red-900/40 border-2 border-red-400 dark:border-red-600 rounded-lg text-center animate-fade-in-custom-v2 shadow-md">
                <XCircleIcon className="w-6 h-6 text-red-600 dark:text-red-400 inline-block mr-2" />
                <span className="text-sm text-red-700 dark:text-red-300 font-semibold align-middle">
                    Koneksi Di-reset oleh: {resetInitiatorIp || "Tidak diketahui"}
                </span>
            </div>
        )}
      </div>

      <Button variant="outline" size="sm" onClick={() => setCurrentStep(0)} className="mt-auto text-sm border-slate-400 hover:bg-slate-200 dark:border-slate-600 dark:hover:bg-slate-700/80 shadow">
        <RefreshCw className="mr-2 h-4 w-4" /> Ulangi Animasi
      </Button>
      
      <style jsx global>{`
        @keyframes packet-move-right-detailed-v3 {
          0% { left: 10%; opacity: 0; transform: translateY(-50%) scale(0.9); }
          15% { opacity: 1; transform: translateY(-50%) scale(1); } /* Muncul */
          85% { opacity: 1; transform: translateY(-50%) scale(1); } /* Diam di tengah */
          100% { left: calc(90% - 70px); opacity: 0; transform: translateY(-50%) scale(0.9); } /* Hilang di kanan (sesuaikan 70px dengan lebar paket) */
        }
        .animate-packet-move-right-detailed {
          animation: packet-move-right-detailed-v3 ${stepDuration / 1000}s ease-in-out forwards;
        }
        @keyframes packet-move-left-detailed-v3 {
          0% { right: 10%; opacity: 0; transform: translateY(-50%) scale(0.9); }
          15% { opacity: 1; transform: translateY(-50%) scale(1); }
          85% { opacity: 1; transform: translateY(-50%) scale(1); }
          100% { right: calc(90% - 70px); opacity: 0; transform: translateY(-50%) scale(0.9); } /* Sesuaikan 70px dengan lebar paket */
        }
        .animate-packet-move-left-detailed {
          animation: packet-move-left-detailed-v3 ${stepDuration / 1000}s ease-in-out forwards;
        }
        @keyframes fade-in-custom-v2 {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0px); }
        }
        .animate-fade-in-custom {
          animation: fade-in-custom-v2 0.7s ease-out forwards;
        }
      `}</style>
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
  const [currentTab, setCurrentTab] = useState<string>("summary");

  const [animationModalOpen, setAnimationModalOpen] = useState<boolean>(false);
  const [animationData, setAnimationData] = useState<{
    type: string;
    sourceIp?: string;
    destinationIp?: string;
    packetNo?: number;
    packetInfo?: string;
    resetInitiatorIp?: string; 
  } | null>(null);

  const fetchData = useCallback(async (isRetry = false) => { if(!isRetry)setIsLoading(true);setError(null);console.log(`[AI_INSIGHTS] Fetching AI analysis data for ID: ${analysisId}`);try{const response=await fetch("/api/analyze-pcap",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({analysisId:analysisId}),});const result=await response.json();if(!response.ok)throw new Error(result.error||result.message||`HTTP error! status: ${response.status}`);if(result&&result.success&&result.analysis){const analysisData=result.analysis;setData(prevData=>({fileName:prevData?.fileName||analysisData.fileName||initialServerData?.fileName,fileSize:prevData?.fileSize||analysisData.fileSize||initialServerData?.fileSize,uploadDate:prevData?.uploadDate||analysisData.uploadDate||initialServerData?.uploadDate,...analysisData,status:"Completed",analystNotes:analysisData.analystNotes||prevData?.analystNotes||initialServerData?.analystNotes||"",samplePacketsForContext: analysisData.samplePacketsForContext || prevData?.samplePacketsForContext || initialServerData?.samplePacketsForContext || []}));setAnalystNotes(analysisData.analystNotes||data?.analystNotes||initialServerData?.analystNotes||"");}else{throw new Error(result.error||"Received unexpected data structure from AI analysis API.");}}catch(err:any){console.error("[AI_INSIGHTS] Error in fetchData:",err);setError(err.message||"An unknown error occurred while fetching AI analysis.");setData(prevData=>({...prevData,status:"Error"}as AiInsightsData));}finally{setIsLoading(false);}}, [analysisId, data?.analystNotes, initialServerData]);
  useEffect(() => { if(initialServerData&&!initialError){setData(initialServerData);setAnalystNotes(initialServerData.analystNotes||"");setIsLoading(false);}else if(initialError){setError(initialError);setIsLoading(false);}else if(!data&&analysisId&&isLoading){fetchData();}else if(data&&!isLoading){/* Data already loaded or no fetch needed initially */}}, [analysisId, initialServerData, initialError, data, isLoading, fetchData]);
  const onPieEnter = useCallback((_: any, index: number) => setActivePieIndex(index), []);
  const handleSaveNotes = async () => { setIsSavingNotes(true);setError(null);try{const response=await fetch(`/api/analysis/${analysisId}/notes`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({notes:analystNotes}),});if(!response.ok){const errorData=await response.json().catch(()=>({message:"Failed to save notes"}));throw new Error(errorData.message||"Failed to save notes");}const saveData=await response.json();console.log("Notes saved successfully:",saveData);setData(prevData=>prevData?{...prevData,analystNotes:analystNotes}:null);alert("Notes saved!");}catch(err:any){console.error("Error saving notes:",err);setError(`Failed to save notes: ${err.message}`);}finally{setIsSavingNotes(false);}};
  const handleExport = (format: 'json' | 'txt') => { if(!data){alert("No data available to export.");return;}let content="";let fileName=`analysis_${analysisId}_${data.fileName||"export"}`;let contentType="text/plain";try{switch(format){case"json":content=JSON.stringify(data,null,2);fileName+=".json";contentType="application/json";break;case"txt":content=`Analysis Report for: ${data.fileName||"N/A"}\n`;content+=`File Size: ${data.fileSize||"N/A"}\n`;content+=`Upload Date: ${data.uploadDate?new Date(data.uploadDate).toLocaleString():"N/A"}\n\n`;content+=`Summary:\n${data.summary||"N/A"}\n\n`;content+=`Threat Analysis:\n${data.threatAnalysis||"N/A"}\n\n`;if(data.iocs&&data.iocs.length>0){content+="IOCs:\n";data.iocs.forEach(ioc=>{content+=`- Type: ${ioc.type}, Value: ${ioc.value}, Context: ${ioc.context}, Confidence: ${ioc.confidence}%\n`;});content+="\n";}content+="Recommendations:\n";if(Array.isArray(data.recommendations)){data.recommendations.forEach(rec=>{content+=`- ${rec.title||"Recommendation"}: ${rec.description||""} (Priority: ${rec.priority||"N/A"})\n`;});}else if(typeof data.recommendations==="string"){content+=data.recommendations;}else{content+="N/A";}fileName+=".txt";contentType="text/plain";break;}const blob=new Blob([content],{type:contentType});const link=document.createElement("a");link.href=URL.createObjectURL(blob);link.download=fileName;document.body.appendChild(link);link.click();document.body.removeChild(link);URL.revokeObjectURL(link.href);}catch(exportError:any){alert(`Failed to export data: ${exportError.message}`);}};
  const handleShare = () => { if(navigator.share){navigator.share({title:`PCAP Analysis: ${data?.fileName||analysisId}`,text:`Check out the AI-driven analysis for this PCAP file: ${data?.summary||"No summary available."}`,url:window.location.href,}).then(()=>console.log("Successful share")).catch((error)=>console.log("Error sharing",error));}else{navigator.clipboard.writeText(window.location.href).then(()=>alert("Link copied to clipboard!")).catch(()=>alert("Could not copy link."));}};
  const handlePrint = () => { window.print(); };

  const handleVisualizeError = (errorDetail: ErrorAnalysisDetail) => {
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
    
    let clientIpForAnim = relatedPacket.source;
    let serverIpForAnim = relatedPacket.destination;
    let resetInitiator = relatedPacket.source; 

    setAnimationData({
      type: errorDetail.errorType,
      clientIp: clientIpForAnim, 
      serverIp: serverIpForAnim,
      packetNo: relatedPacket.no,
      packetInfo: relatedPacket.info,
      resetInitiatorIp: resetInitiator 
    });
    setAnimationModalOpen(true);
  };


  if (isLoading && !data) { return(<div className="flex flex-col items-center justify-center min-h-[300px] p-4"><div className="text-center"><Loader2 className="w-12 h-12 text-blue-500 animate-spin mx-auto mb-4"/><h2 className="text-xl font-semibold mb-2">Loading AI Insights...</h2><p className="text-gray-600 dark:text-gray-300 mb-4">The AI is analyzing your PCAP data. This may take a few moments.</p><Progress value={30}className="w-full max-w-md mx-auto"/><p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Analysis ID: {analysisId}</p></div></div>); }
  if (error && !isLoading && (!data || data.status === 'Error')) { return(<Alert variant="destructive"className="max-w-2xl mx-auto my-8"><AlertCircle className="h-4 w-4"/><AlertTitle>Error Fetching Analysis</AlertTitle><AlertDescription><p>{error}</p><p>Analysis ID: {analysisId}</p><Button onClick={()=>fetchData(true)}variant="outline"className="mt-4"disabled={isLoading}><RefreshCw className="mr-2 h-4 w-4"/>{isLoading?"Retrying...":"Try Again"}</Button></AlertDescription></Alert>); }
  if (!data && !isLoading) { return(<Alert className="max-w-2xl mx-auto my-8"><Info className="h-4 w-4"/><AlertTitle>No AI Insights Available</AlertTitle><AlertDescription><p>AI insights could not be loaded for analysis ID: {analysisId}. The analysis might still be processing or an issue occurred.</p><Button onClick={()=>fetchData(true)}variant="outline"className="mt-4"disabled={isLoading}><RefreshCw className="mr-2 h-4 w-4"/>{isLoading?"Refreshing...":"Refresh"}</Button></AlertDescription></Alert>); }
  
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
                  {data.voipAnalysisReport && (data.voipAnalysisReport.detectedCalls && data.voipAnalysisReport.detectedCalls.length > 0 || data.voipAnalysisReport.potentialIssues && data.voipAnalysisReport.potentialIssues.length > 0) && (
                    <TabsTrigger value="voip" className="flex items-center text-xs sm:text-sm"><PhoneOff className="mr-1 sm:mr-2 h-4 w-4" />VoIP Analysis</TabsTrigger>
                  )}
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
                <TabsContent value="recommendations"><Card><CardHeader><CardTitle className="flex items-center text-lg"><MessageSquare className="mr-2 text-green-500"/>Recommended Actions</CardTitle></CardHeader><CardContent className="prose dark:prose-invert max-w-none text-sm md:text-base">{data.recommendations&&Array.isArray(data.recommendations)&&data.recommendations.length>0?(<ul className="list-disc pl-5 space-y-2">{data.recommendations.map((rec,index)=>(<li key={index}><strong className="font-medium">{rec.title||`Recommendation ${index+1}`}</strong> (Priority: {rec.priority||"N/A"}):<p className="text-sm ml-4">{rec.description||"No detailed description."}</p></li>))}</ul>):(<p>{typeof data.recommendations==="string"?data.recommendations:"No specific recommendations provided by AI."}</p>)}</CardContent></Card></TabsContent>
                <TabsContent value="timeline"><Card><CardHeader><CardTitle className="flex items-center text-lg"><Clock className="mr-2 text-fuchsia-500"/>Event Timeline</CardTitle></CardHeader><CardContent>{data.timeline&&data.timeline.length>0?(<div className="relative pl-6 space-y-6 border-l-2 border-gray-200 dark:border-gray-700">{data.timeline.map((event,index)=>(<div key={index}className="relative"><div className={`absolute -left-[calc(0.75rem+1px)] mt-1.5 flex h-6 w-6 items-center justify-center rounded-full ${event.severity==="error"?"bg-red-500":event.severity==="warning"?"bg-yellow-500":"bg-blue-500"} text-white text-xs font-semibold`}>{event.severity==="error"?<AlertCircle size={14}/>:event.severity==="warning"?<AlertTriangle size={14}/>:<Info size={14}/>}</div><div className="ml-4"><p className="font-medium text-sm">{event.event||"Unknown Event"}</p><p className="text-xs text-muted-foreground">{event.time&&!event.time.includes("Packet Sample")?new Date(event.time).toLocaleString():event.time||"N/A"}</p></div></div>))}</div>):(<p className="text-center text-gray-500 dark:text-gray-400 py-4">No timeline events provided by AI.</p>)}</CardContent></Card></TabsContent>
                <TabsContent value="visuals"className="space-y-6">{data.protocolDistribution&&data.protocolDistribution.length>0&&(<Card><CardHeader><CardTitle className="flex items-center text-lg"><PieChartIcon className="mr-2 text-purple-500"/>Protocol Distribution</CardTitle></CardHeader><CardContent style={{width:"100%",height:300}}><ResponsiveContainer><PieChart><Pie activeIndex={activePieIndex}activeShape={renderActiveShape}data={data.protocolDistribution}cx="50%"cy="50%"innerRadius={60}outerRadius={100}fill="#8884d8"dataKey="value"onMouseEnter={onPieEnter}>{data.protocolDistribution.map((entry,index)=>(<Cell key={`cell-${index}`}fill={entry.fill||COLORS[index%COLORS.length]}/>))}</Pie><RechartsTooltip/><Legend layout="vertical"align="right"verticalAlign="middle"iconSize={10}wrapperStyle={{fontSize:"12px"}}/></PieChart></ResponsiveContainer></CardContent></Card>)} {data.statistics?.topTalkers&&data.statistics.topTalkers.length>0&&data.statistics.topTalkers[0].ip!=="No identifiable IP traffic"&&(<Card><CardHeader><CardTitle className="flex items-center text-lg"><BarChart2 className="mr-2 text-green-500"/>Top Talkers (by Packets)</CardTitle></CardHeader><CardContent style={{width:"100%",height:300}}><ResponsiveContainer><BarChart data={data.statistics.topTalkers}layout="vertical"margin={{top:5,right:30,left:20,bottom:5}}><CartesianGrid strokeDasharray="3 3"/><XAxis type="number"/><YAxis dataKey="ip"type="category"width={150}interval={0}tick={{fontSize:10}}/><RechartsTooltip/><Legend wrapperStyle={{fontSize:"12px"}}/><Bar dataKey="packets"name="Total Packets"fill="#82ca9d"/></BarChart></ResponsiveContainer></CardContent></Card>)}</TabsContent>
                {data.performanceMetrics&&(<TabsContent value="performance"><Card><CardHeader><CardTitle className="flex items-center text-lg"><Activity className="mr-2 text-cyan-500"/>Performance</CardTitle></CardHeader><CardContent className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-sm md:text-base"><div><strong>Total Packets (in file):</strong> {data.performanceMetrics.totalPackets?.toLocaleString()||data.statistics?.totalPacketsInFile?.toLocaleString()||"N/A"}</div><div><strong>Total Bytes (in file):</strong> {data.performanceMetrics.totalBytes?.toLocaleString()||data.statistics?.totalBytesInFile?.toLocaleString()||"N/A"}</div><div><strong>Capture Duration:</strong> {data.performanceMetrics.captureDuration||"N/A"}</div><div><strong>Avg Packet Rate:</strong> {data.performanceMetrics.averagePacketRate||"N/A"}</div></CardContent></Card></TabsContent>)}
                
                {data.voipAnalysisReport && (data.voipAnalysisReport.detectedCalls && data.voipAnalysisReport.detectedCalls.length > 0 || data.voipAnalysisReport.potentialIssues && data.voipAnalysisReport.potentialIssues.length > 0) && (
                  <TabsContent value="voip">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center text-lg">
                          <PhoneOff className="mr-2 text-indigo-500" /> VoIP/Call Analysis
                        </CardTitle>
                        <CardDescription>
                          {data.voipAnalysisReport.summary || "Insights into Voice over IP and call-related traffic."}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {data.voipAnalysisReport.detectedCalls && data.voipAnalysisReport.detectedCalls.length > 0 && (
                          <div>
                            <h4 className="font-semibold mb-2 text-base">Detected Calls:</h4>
                            <Accordion type="multiple" className="w-full">
                              {data.voipAnalysisReport.detectedCalls.map((call, index) => (
                                <AccordionItem value={`call-${index}`} key={call.callId || `call-${index}`}>
                                  <AccordionTrigger className="text-sm hover:no-underline">
                                    Call from {call.caller || "Unknown"} to {call.callee || "Unknown"} - <Badge variant={call.status === 'Failed' ? 'destructive' : 'secondary'}>{call.status}</Badge>
                                  </AccordionTrigger>
                                  <AccordionContent className="text-xs space-y-1 pl-4">
                                    {call.callId && <p><strong>Call ID:</strong> {call.callId}</p>}
                                    {call.startTime && <p><strong>Start Time:</strong> {new Date(call.startTime).toLocaleString()}</p>}
                                    {call.duration && <p><strong>Duration:</strong> {call.duration}</p>}
                                    {call.failureReason && <p><strong>Failure Reason:</strong> {call.failureReason}</p>}
                                    {call.relatedPackets && call.relatedPackets.length > 0 && <p><strong>Related Packets (No.):</strong> {call.relatedPackets.join(', ')}</p>}
                                  </AccordionContent>
                                </AccordionItem>
                              ))}
                            </Accordion>
                          </div>
                        )}
                        {data.voipAnalysisReport.potentialIssues && data.voipAnalysisReport.potentialIssues.length > 0 && (
                           <div>
                            <h4 className="font-semibold mt-4 mb-2 text-base">Potential VoIP Issues:</h4>
                             <ul className="list-disc pl-5 space-y-2 text-sm">
                              {data.voipAnalysisReport.potentialIssues.map((issue, index) => (
                                <li key={index}>
                                  <strong>{issue.issueType}:</strong> {issue.description}
                                  {issue.evidence && <em className="block text-xs text-muted-foreground">Evidence: {issue.evidence}</em>}
                                  {issue.recommendation && <p className="text-xs mt-0.5">Recommendation: {issue.recommendation}</p>}
                                </li>
                              ))}
                            </ul>
                           </div>
                        )}
                         {(!data.voipAnalysisReport.detectedCalls || data.voipAnalysisReport.detectedCalls.length === 0) && 
                          (!data.voipAnalysisReport.potentialIssues || data.voipAnalysisReport.potentialIssues.length === 0) && (
                            <p className="text-sm text-muted-foreground">No specific VoIP call details or issues were highlighted by the AI.</p>
                         )}
                      </CardContent>
                    </Card>
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
            <Textarea value={analystNotes} onChange={(e) => setAnalystNotes(e.target.value)} placeholder="Type your notes here..." rows={5} className="mb-3 text-sm md:text-base" />
            <Button onClick={handleSaveNotes} disabled={isSavingNotes} size="sm">
              {isSavingNotes ? (<><Loader2 className="mr-2 h-4 w-4 animate-spin"/>Saving...</>) : "Save Notes"}
            </Button>
          </CardContent>
        </Card>

        {animationModalOpen && animationData && (
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
              
              {animationData.type && animationData.type.toLowerCase().includes("reset") && (
                <TcpResetAnimation 
                  clientIp={animationData.sourceIp} 
                  serverIp={animationData.destinationIp}
                  resetInitiatorIp={animationData.resetInitiatorIp}
                  packetInfo={animationData.packetInfo}
                  errorType={animationData.type}
                />
              )}
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
