"use client";

import { useState, useEffect } from "react";
import { 
    Card, CardContent, CardDescription, 
    CardHeader, CardTitle, CardFooter 
} from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { 
    Tabs, TabsContent, TabsList, TabsTrigger 
} from "@/components/ui/tabs";
import { 
    Accordion, AccordionContent, AccordionItem, AccordionTrigger 
} from "@/components/ui/accordion";
import { 
    Loader2, AlertTriangle, Shield, Activity, Network, 
    FileWarning, RefreshCw, Zap, Search, ExternalLink, 
    EyeOff, ListChecks, History, ShieldAlert, Info, Users, 
    FileText, BarChart3, Route, Lightbulb 
} from "lucide-react";
import { IOCList } from "@/components/ioc-list";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
// --- TAMBAHKAN IMPOR TOOLTIP DI SINI ---
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

// Interface Insight dan AIAnalysis tetap sama seperti versi terakhir.
// ... (kode interface AIAnalysis dan Insight) ...
interface Insight {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  recommendation?: string;
  category: "malware" | "anomaly" | "exfiltration" | "vulnerability" | "reconnaissance" | "policy-violation" | "benign-but-noteworthy";
  affectedHosts?: string[];
  detailedAnalysis?: string;
  relatedPackets?: number[];
  timeline?: {
    time: string;
    event: string;
  }[]; 
  mitigationSteps?: string[];
  references?: {
    title: string;
    url: string;
  }[];
}

interface AIAnalysis {
  summary: string;
  threatLevel: "low" | "medium" | "high" | "critical";
  findings: Insight[];
  statistics?: { 
    totalPacketsInFile?: number;
    packetsProcessedForStats?: number;
    protocols?: { [key: string]: number; };
    topTalkers?: { 
        ip: string; 
        packets: number; 
        bytes: number;
        sentPackets?: number;
        receivedPackets?: number;
        sentBytes?: number;
        receivedBytes?: number;
    }[];
    anomalyScore?: number;
  };
  timeline?: { 
    time: string;
    event: string;
    severity: "info" | "warning" | "error";
  }[];
  recommendations?: {
    title: string;
    description: string;
    priority: "low" | "medium" | "high";
  }[];
  iocs?: {
    type: "ip" | "domain" | "url" | "hash";
    value: string;
    context: string;
    confidence: number;
  }[];
}


export function AIInsights({ analysisId }: AIInsightsProps) {
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(true); 
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [selectedInsight, setSelectedInsight] = useState<Insight | null>(null);

  const runAnalysis = async () => {
    if (!analysisId) {
      setError("Invalid analysis ID");
      setLoading(false);
      setAnalyzing(false);
      return;
    }
    console.log(`[AI_INSIGHTS_FE] Initiating analysis for ID: ${analysisId}`);
    setLoading(true);
    setAnalyzing(true);
    setProgress(0);
    setError(null);
    setAnalysis(null); 
    setSelectedInsight(null);

    let progressInterval: NodeJS.Timeout | null = null;

    try {
      let currentProgress = 0;
      const totalSteps = 100; 
      const timePerStep = 200; 

      progressInterval = setInterval(() => {
        currentProgress++;
        const newProgress = Math.min(95, Math.floor((currentProgress / (totalSteps * 0.95)) * 95));
        setProgress(newProgress);
        if (newProgress >= 95) {
          if (progressInterval) clearInterval(progressInterval);
        }
      }, timePerStep / (totalSteps/100)); 

      console.log(`[AI_INSIGHTS_FE] Requesting AI analysis from API for analysisId: ${analysisId}`);
      const response = await fetch("/api/analyze-pcap", {
        method: "POST",
        headers: { "Content-Type": "application/json", },
        body: JSON.stringify({ analysisId }),
      });

      if (progressInterval) clearInterval(progressInterval);

      if (!response.ok) {
        let errorData;
        try {
          errorData = await response.json();
        } catch (e) {
          errorData = { error: `Analysis request failed with status: ${response.status} ${response.statusText}` };
        }
        console.error("[AI_INSIGHTS_FE] API error response:", errorData);
        throw new Error(errorData.error || `Analysis failed: ${response.statusText}`);
      }

      const data = await response.json();
      console.log("[AI_INSIGHTS_FE] AI Analysis data received from API:", data);

      if (data.success && data.analysis) {
        const normalizedAnalysis: AIAnalysis = {
            summary: data.analysis.summary || "No summary provided.",
            threatLevel: data.analysis.threatLevel || "low",
            findings: data.analysis.findings || [],
            statistics: { 
                totalPacketsInFile: data.analysis.statistics?.totalPacketsInFile || 0,
                packetsProcessedForStats: data.analysis.statistics?.packetsProcessedForStats || data.analysis.statistics?.totalPacketsInFile || 0,
                protocols: data.analysis.statistics?.protocols || {},
                topTalkers: data.analysis.statistics?.topTalkers || [],
                anomalyScore: data.analysis.statistics?.anomalyScore,
            },
            timeline: data.analysis.timeline || [],
            recommendations: data.analysis.recommendations || [],
            iocs: data.analysis.iocs || [],
        };
        setAnalysis(normalizedAnalysis);
        setProgress(100);
      } else {
        throw new Error(data.error || "Analysis data missing in successful response.");
      }
    } catch (err) {
      if (progressInterval) clearInterval(progressInterval);
      console.error("[AI_INSIGHTS_FE] Error during analysis fetch or processing:", err);
      setError(err instanceof Error ? err.message : "An unknown error occurred during AI analysis.");
      setProgress(0);
    } finally {
      setAnalyzing(false); 
      setLoading(false); 
    }
  };

  useEffect(() => {
    if (analysisId) {
      runAnalysis();
    }
  }, [analysisId]);

  const getSeverityColor = (severity?: string) => { 
    if (!severity) return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
    switch (severity.toLowerCase()) {
      case "low": return "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300";
      case "medium": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300";
      case "high": return "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300";
      case "critical": return "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
    }
  };

  const getSeverityBgColor = (severity?: string) => { 
    if (!severity) return "bg-slate-50 border-slate-200 dark:bg-slate-800 dark:border-slate-700";
    switch (severity.toLowerCase()) {
        case "low": return "bg-blue-50 border-blue-300 dark:bg-blue-900/40 dark:border-blue-700";
        case "medium": return "bg-yellow-50 border-yellow-300 dark:bg-yellow-900/40 dark:border-yellow-700";
        case "high": return "bg-orange-50 border-orange-300 dark:bg-orange-900/40 dark:border-orange-700";
        case "critical": return "bg-red-50 border-red-300 dark:bg-red-900/40 dark:border-red-700";
        default: return "bg-slate-50 border-slate-200 dark:bg-slate-800 dark:border-slate-700";
    }
  };
  
  const getCategoryIcon = (category?: string) => { 
    if(!category) return <Info className="h-5 w-5 text-gray-500" />;
    switch (category.toLowerCase()) {
      case "malware": return <ShieldAlert className="h-5 w-5 text-red-500" />;
      case "anomaly": return <Activity className="h-5 w-5 text-yellow-500" />;
      case "exfiltration": return <Route className="h-5 w-5 text-purple-500" />;
      case "vulnerability": return <FileWarning className="h-5 w-5 text-orange-500" />;
      case "reconnaissance": return <Search className="h-5 w-5 text-blue-500" />;
      case "policy-violation": return <FileWarning className="h-5 w-5 text-indigo-500" />;
      case "benign-but-noteworthy": return <Info className="h-5 w-5 text-green-500" />;
      default: return <AlertTriangle className="h-5 w-5 text-gray-500" />;
    }
  };

  const getTimelineSeverityColor = (severity?: string) => { 
    if (!severity) return "bg-gray-100 border-gray-200 dark:bg-gray-700/30 dark:border-gray-600";
    switch (severity.toLowerCase()) {
      case "info": return "bg-blue-100 border-blue-300 dark:bg-blue-900/30 dark:border-blue-700";
      case "warning": return "bg-yellow-100 border-yellow-300 dark:bg-yellow-800/30 dark:border-yellow-700";
      case "error": return "bg-red-100 border-red-300 dark:bg-red-900/30 dark:border-red-700";
      default: return "bg-gray-100 border-gray-200 dark:bg-gray-700/30 dark:border-gray-600";
    }
  };

  const getPriorityColor = (priority?: string) => { 
    if(!priority) return "bg-gray-100 text-gray-800";
    switch (priority.toLowerCase()) {
      case "low": return "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300";
      case "medium": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300";
      case "high": return "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
    }
  };

  const handleInsightClick = (insight: Insight) => {
    setSelectedInsight(selectedInsight?.id === insight.id ? null : insight);
  };

  // ... (Kode untuk state loading, error, dan !analysis tetap sama)
  if (loading && analyzing) { 
    return (
      <div className="space-y-6 animate-pulse">
        <Card className="shadow-lg">
          <CardHeader className="pb-3">
            <Skeleton className="h-8 w-3/4" />
            <Skeleton className="h-4 w-1/2 mt-1" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-4 w-full mb-2" />
            <Skeleton className="h-4 w-5/6" />
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-6">
                <Skeleton className="h-24 w-full rounded-lg" />
                <Skeleton className="h-24 w-full rounded-lg" />
                <Skeleton className="h-24 w-full rounded-lg" />
            </div>
          </CardContent>
        </Card>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
                <Skeleton className="h-64 w-full rounded-lg"/>
                <Skeleton className="h-48 w-full rounded-lg"/>
            </div>
            <div className="lg:col-span-1 space-y-6">
                <Skeleton className="h-80 w-full rounded-lg"/>
            </div>
        </div>
      </div>
    );
  }
  
  if (error) { 
    return (
      <Alert variant="destructive" className="shadow-md">
          <AlertTriangle className="h-5 w-5" />
          <AlertTitle className="text-lg">AI Analysis Error</AlertTitle>
          <AlertDescription className="mt-2 space-y-3">
              <p>We encountered an issue while generating AI insights for this PCAP file.</p>
              <p className="text-sm font-mono bg-red-100/50 dark:bg-red-900/30 p-2 rounded">Details: {error}</p>
              <Button onClick={runAnalysis} className="mt-2" disabled={analyzing || loading}> 
                  <RefreshCw className={`mr-2 h-4 w-4 ${analyzing ? "animate-spin" : ""}`}/>Try Again 
              </Button>
          </AlertDescription>
      </Alert>
    );
  }

  if (!analysis && !analyzing && !loading) { 
    return (
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center"><Info className="mr-2 h-6 w-6 text-muted-foreground"/>AI Insights</CardTitle>
          <CardDescription>No AI analysis data available for this file.</CardDescription>
        </CardHeader>
        <CardContent className="text-center py-12 text-muted-foreground">
          <FileWarning className="h-16 w-16 mx-auto mb-4 text-gray-400"/>
          <p>Could not load or generate AI insights.</p>
          <Button onClick={runAnalysis} className="mt-6" disabled={analyzing || loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${analyzing ? "animate-spin" : ""}`} />
            Retry Analysis
          </Button>
        </CardContent>
      </Card>
    );
  }
  
  if (!analysis) {
      return (
          <div className="flex justify-center items-center h-80">
              <Loader2 className="h-12 w-12 animate-spin text-primary" />
              <p className="ml-3 text-muted-foreground">Preparing analysis...</p>
          </div>
      );
  }
  // ----- Tampilan Utama Setelah Data AI Analysis Diterima -----
  // Baris 340
  return (
    <TooltipProvider> {/* Baris 341 - Sekarang sudah diimpor */}
      <div className="space-y-8"> {/* Baris 342 */}
        {/* ... (sisa JSX dari versi terakhir yang sudah diimprove UI-nya) ... */}
        {/* Card Ringkasan Analisis */}
        <Card className={`${getSeverityBgColor(analysis.threatLevel)} border-2 shadow-xl rounded-xl`}>
            <CardHeader className="pb-4 px-6 pt-5"> 
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2">
                <div className="flex items-center gap-3">
                    <Lightbulb className={`h-8 w-8 ${getSeverityColor(analysis.threatLevel).split(' ')[1]}`} />
                    <CardTitle className="text-2xl lg:text-3xl font-bold">AI Threat Summary</CardTitle>
                </div>
                <Badge className={`${getSeverityColor(analysis.threatLevel)} px-4 py-1.5 text-sm rounded-full self-start sm:self-center`}>
                  {analysis.threatLevel?.charAt(0).toUpperCase() + (analysis.threatLevel?.slice(1) || '')} Threat Level
                </Badge>
              </div>
              {analysis.statistics && (analysis.statistics.packetsProcessedForStats !== undefined || analysis.statistics.totalPacketsInFile !== undefined) && (
                <CardDescription className="mt-2 text-base">
                    Analysis based on {(analysis.statistics.packetsProcessedForStats ?? analysis.statistics.totalPacketsInFile ?? 0).toLocaleString()} packets from the capture.
                </CardDescription>
              )}
            </CardHeader>
            <CardContent className="px-6 pb-6">
              <p className="text-md leading-relaxed text-foreground/90">{analysis.summary}</p>
              
              {analysis.statistics && (analysis.statistics.anomalyScore !== undefined || (analysis.statistics.topTalkers && analysis.statistics.topTalkers.length > 0) || (analysis.findings && analysis.findings.length > 0) ) && (
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 mt-6 pt-4 border-t dark:border-slate-700">
                    {analysis.findings?.length > 0 && (
                        <div className="bg-background/60 dark:bg-slate-800/50 p-4 rounded-lg shadow">
                            <div className="flex items-center text-sm font-semibold text-red-600 dark:text-red-400 mb-1">
                                <ShieldAlert className="h-5 w-5 mr-2" />
                                Key Findings
                            </div>
                            <div className="text-3xl font-bold">{analysis.findings.length}</div>
                            <p className="text-xs text-muted-foreground">
                                {analysis.findings.filter(f => f.severity === 'critical').length} critical, {analysis.findings.filter(f => f.severity === 'high').length} high
                            </p>
                        </div>
                    )}
                    {analysis.statistics.anomalyScore !== undefined && (
                        <div className="bg-background/60 dark:bg-slate-800/50 p-4 rounded-lg shadow">
                            <div className="flex items-center text-sm font-semibold text-yellow-600 dark:text-yellow-400 mb-1">
                            <Activity className="h-5 w-5 mr-2" />
                            Anomaly Score
                            </div>
                            <div className="text-3xl font-bold">{analysis.statistics.anomalyScore}/100</div>
                        </div>
                    )}
                    {analysis.statistics.topTalkers && analysis.statistics.topTalkers.length > 0 && analysis.statistics.topTalkers[0] && (
                        <div className="bg-background/60 dark:bg-slate-800/50 p-4 rounded-lg shadow">
                            <div className="flex items-center text-sm font-semibold text-blue-600 dark:text-blue-400 mb-1">
                                <Users className="h-5 w-5 mr-2" />
                                Top Talker (IP)
                            </div>
                            <div className="text-xl font-bold truncate" title={analysis.statistics.topTalkers[0].ip || "N/A"}>
                                {analysis.statistics.topTalkers[0].ip || "N/A"}
                            </div>
                            <p className="text-xs text-muted-foreground">
                               {(analysis.statistics.topTalkers[0].packets || 0).toLocaleString()} pkts
                            </p>
                        </div>
                    )}
                </div>
              )}
            </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-7 gap-x-8 gap-y-6">
            <div className="lg:col-span-4 space-y-6">
                {analysis.findings && analysis.findings.length > 0 && (
                    <Card className="shadow-lg">
                        <CardHeader>
                        <CardTitle className="text-xl flex items-center">
                            <ListChecks className="h-6 w-6 mr-3 text-primary"/> Security Findings
                        </CardTitle>
                        <CardDescription>AI-detected security issues and potential threats in your network traffic.</CardDescription>
                        </CardHeader>
                        <CardContent>
                        <Accordion type="multiple" className="w-full">
                            {analysis.findings.map((finding) => (
                            <AccordionItem value={finding.id} key={finding.id} className="border-b dark:border-slate-700 last:border-b-0">
                                <AccordionTrigger className={`py-4 px-2 text-left hover:no-underline rounded-md hover:bg-muted/50 dark:hover:bg-slate-800/70 ${selectedInsight?.id === finding.id ? 'bg-muted dark:bg-slate-800' : ''}`}>
                                    <div className="flex items-center gap-3 w-full">
                                        <span className={`p-1.5 rounded-full ${getSeverityBgColor(finding.severity)} border dark:border-slate-700`}>
                                            {getCategoryIcon(finding.category)}
                                        </span>
                                        <div className="flex-1 min-w-0">
                                            <h4 className="font-semibold text-md truncate" title={finding.title}>{finding.title}</h4>
                                            <p className="text-xs text-muted-foreground line-clamp-1">{finding.description}</p>
                                        </div>
                                        <Badge className={`${getSeverityColor(finding.severity)} text-xs self-start mt-1 px-2.5 py-0.5`}>
                                            {finding.severity?.charAt(0).toUpperCase() + (finding.severity?.slice(1) || '')}
                                        </Badge>
                                    </div>
                                </AccordionTrigger>
                                <AccordionContent className="pt-2 pb-4 px-3 space-y-3 text-sm leading-relaxed bg-slate-50 dark:bg-slate-800/50 rounded-b-md">
                                    <p><strong className="font-medium text-foreground/80">Description:</strong> {finding.description}</p>
                                    {finding.detailedAnalysis && (
                                        <p><strong className="font-medium text-foreground/80">Detailed Analysis:</strong> {finding.detailedAnalysis}</p>
                                    )}
                                    {finding.affectedHosts && finding.affectedHosts.length > 0 && (
                                        <div>
                                        <strong className="font-medium text-foreground/80">Affected Hosts:</strong>
                                        <div className="flex flex-wrap gap-1.5 mt-1">
                                            {finding.affectedHosts.map((host, index) => (
                                            <Badge key={index} variant="secondary" className="font-mono text-xs">{host}</Badge>
                                            ))}
                                        </div>
                                        </div>
                                    )}
                                    {finding.relatedPackets && finding.relatedPackets.length > 0 && (
                                        <div>
                                        <strong className="font-medium text-foreground/80">Related Packet Samples (Indices):</strong>
                                        <div className="flex flex-wrap gap-1.5 mt-1">
                                            {finding.relatedPackets.map((packetId, index) => (
                                            <Badge key={index} variant="outline" className="text-xs">#{packetId}</Badge>
                                            ))}
                                        </div>
                                        </div>
                                    )}
                                    {finding.recommendation && (
                                        <p className="pt-3 mt-3 border-t dark:border-slate-700"><strong className="font-medium text-foreground/80">Recommendation:</strong> {finding.recommendation}</p>
                                    )}
                                    {finding.mitigationSteps && finding.mitigationSteps.length > 0 && (
                                        <div className="pt-3 mt-3 border-t dark:border-slate-700">
                                            <strong className="font-medium text-foreground/80 mb-1 block">Mitigation Steps:</strong>
                                            <ul className="list-disc pl-5 space-y-1 text-xs">
                                                {finding.mitigationSteps.map((step, idx) => <li key={idx}>{step}</li>)}
                                            </ul>
                                        </div>
                                    )}
                                    {finding.references && finding.references.length > 0 && (
                                        <div className="pt-3 mt-3 border-t dark:border-slate-700">
                                            <strong className="font-medium text-foreground/80 mb-1 block">References:</strong>
                                            <ul className="space-y-1">
                                            {finding.references.map((ref, index) => (
                                                <li key={index}>
                                                <a href={ref.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 dark:text-blue-400 hover:underline text-xs flex items-center">
                                                    {ref.title} <ExternalLink className="h-3 w-3 ml-1.5"/>
                                                </a>
                                                </li>
                                            ))}
                                            </ul>
                                        </div>
                                    )}
                                </AccordionContent>
                            </AccordionItem>
                            ))}
                        </Accordion>
                        </CardContent>
                    </Card>
                )}

                {analysis.recommendations && analysis.recommendations.length > 0 && (
                    <Card className="shadow-lg">
                        <CardHeader>
                        <CardTitle className="text-xl flex items-center">
                            <Zap className="h-6 w-6 mr-3 text-primary"/> General Recommendations
                        </CardTitle>
                        <CardDescription>Overall suggestions to improve security posture based on the analysis.</CardDescription>
                        </CardHeader>
                        <CardContent>
                        <div className="space-y-4">
                            {analysis.recommendations.map((rec, index) => (
                            <div key={index} className="p-4 border dark:border-slate-700 rounded-lg bg-card flex items-start shadow-sm hover:shadow-md transition-shadow">
                                <div className={`flex-shrink-0 p-2.5 rounded-full ${getPriorityColor(rec.priority).replace('text-', 'bg-').replace('800', '100 dark:bg-opacity-30')} mr-4`}>
                                {rec.priority === "high" ? <Zap className={`h-5 w-5 ${getPriorityColor(rec.priority).split(' ')[1]}`} />
                                : rec.priority === "medium" ? <AlertTriangle className={`h-5 w-5 ${getPriorityColor(rec.priority).split(' ')[1]}`} />
                                : <Shield className={`h-5 w-5 ${getPriorityColor(rec.priority).split(' ')[1]}`} />}
                                </div>
                                <div className="flex-1">
                                <div className="flex items-baseline justify-between">
                                    <h4 className="font-semibold text-md">{rec.title}</h4>
                                    <Badge className={`${getPriorityColor(rec.priority)} text-xs px-2.5 py-0.5`}>
                                    {rec.priority?.charAt(0).toUpperCase() + (rec.priority?.slice(1) || '')}
                                    </Badge>
                                </div>
                                <p className="text-sm text-muted-foreground mt-1 leading-snug">{rec.description}</p>
                                </div>
                            </div>
                            ))}
                        </div>
                        </CardContent>
                    </Card>
                )}
            </div>

            <div className="lg:col-span-3 space-y-6">
                {analysis.iocs && analysis.iocs.length > 0 && (
                    <Card className="shadow-lg">
                    <CardHeader>
                        <CardTitle className="text-xl flex items-center">
                            <FileText className="h-6 w-6 mr-3 text-primary"/> Indicators of Compromise
                        </CardTitle>
                        <CardDescription>Potential IOCs extracted from the PCAP analysis.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <IOCList iocs={analysis.iocs} />
                    </CardContent>
                    </Card>
                )}

                {analysis.timeline && analysis.timeline.length > 0 && (
                    <Card className="shadow-lg">
                    <CardHeader>
                        <CardTitle className="text-xl flex items-center">
                            <History className="h-6 w-6 mr-3 text-primary"/> Activity Timeline
                        </CardTitle>
                        <CardDescription>Chronological view of significant detected events.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <ScrollArea className="max-h-[400px] pr-3">
                            <div className="relative pl-3 border-l-2 border-muted dark:border-slate-700 space-y-5">
                                {analysis.timeline.map((event, index) => ( 
                                    <div key={index} className="relative pl-5">
                                        <div className={`absolute left-[-7px] top-1.5 w-3 h-3 rounded-full border-2 border-background dark:border-slate-900 ${getTimelineSeverityColor(event.severity).split(' ')[0].replace('bg-', 'border-')}`}></div>
                                        <div className={`absolute left-[-6px] top-[7px] w-2.5 h-2.5 rounded-full ${getTimelineSeverityColor(event.severity).split(' ')[0]}`}></div>
                                        
                                        <p className="text-xs text-muted-foreground mb-0.5">{event.time}</p>
                                        <p className={`text-sm font-medium p-2.5 rounded-md shadow-sm ${getTimelineSeverityColor(event.severity)} border`}>
                                            {event.event}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </ScrollArea>
                    </CardContent>
                    </Card>
                )}
            </div>
        </div>
      </>
    </div>
    </TooltipProvider>
  );
}
