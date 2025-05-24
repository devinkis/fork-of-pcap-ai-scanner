"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
    Loader2, AlertTriangle, Shield, Activity, Network, FileWarning, 
    RefreshCw, Zap, Search, ExternalLink, EyeOff, ListChecks, 
    History, ShieldAlert, Info, Users, FileText, BarChart3, Route 
} from "lucide-react";
import { IOCList } from "@/components/ioc-list";
import { ScrollArea } from "@/components/ui/scroll-area";

interface AIInsightsProps {
  analysisId: string;
}

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
  statistics: {
    totalPacketsInFile: number;
    packetsProcessedForStats?: number;
    protocols: { [key: string]: number; };
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
    console.log(`[AI_INSIGHTS_COMPONENT] Initiating analysis for ID: ${analysisId}`);
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

      console.log(`[AI_INSIGHTS_COMPONENT] Requesting AI analysis from API for analysisId: ${analysisId}`);
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
        console.error("[AI_INSIGHTS_COMPONENT] API error response:", errorData);
        throw new Error(errorData.error || `Analysis failed: ${response.statusText}`);
      }

      const data = await response.json();
      console.log("[AI_INSIGHTS_COMPONENT] AI Analysis data received from API:", data);

      if (data.success && data.analysis) {
        const normalizedAnalysis = {
            ...data.analysis,
            statistics: {
                totalPacketsInFile: data.analysis.statistics?.totalPacketsInFile || 0,
                packetsProcessedForStats: data.analysis.statistics?.packetsProcessedForStats || data.analysis.statistics?.totalPacketsInFile || 0,
                protocols: data.analysis.statistics?.protocols || {},
                topTalkers: data.analysis.statistics?.topTalkers || [],
                anomalyScore: data.analysis.statistics?.anomalyScore,
            },
            findings: data.analysis.findings || [],
            iocs: data.analysis.iocs || [],
            recommendations: data.analysis.recommendations || [],
            timeline: data.analysis.timeline || [],
        };
        setAnalysis(normalizedAnalysis);
        setProgress(100);
      } else {
        throw new Error(data.error || "Analysis data missing in successful response.");
      }
    } catch (err) {
      if (progressInterval) clearInterval(progressInterval);
      console.error("[AI_INSIGHTS_COMPONENT] Error during analysis fetch or processing:", err);
      setError(err instanceof Error ? err.message : "An unknown error occurred during analysis.");
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
    switch (severity) {
      case "low": return "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300";
      case "medium": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300";
      case "high": return "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300";
      case "critical": return "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
    }
  };

  const getSeverityBgColor = (severity?: string) => {
    if (!severity) return "bg-gray-50 border-gray-200 dark:bg-gray-800 dark:border-gray-700";
    switch (severity) {
      case "low": return "bg-blue-50 border-blue-200 dark:bg-blue-900/30 dark:border-blue-800";
      case "medium": return "bg-yellow-50 border-yellow-200 dark:bg-yellow-900/30 dark:border-yellow-800";
      case "high": return "bg-orange-50 border-orange-200 dark:bg-orange-900/30 dark:border-orange-800";
      case "critical": return "bg-red-50 border-red-200 dark:bg-red-900/30 dark:border-red-800";
      default: return "bg-gray-50 border-gray-200 dark:bg-gray-800 dark:border-gray-700";
    }
  };
  
  const getCategoryIcon = (category?: string) => {
    if(!category) return <Info className="h-5 w-5 text-gray-500" />;
    switch (category) {
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
    switch (severity) {
      case "info": return "bg-blue-100 border-blue-200 dark:bg-blue-900/30 dark:border-blue-700";
      case "warning": return "bg-yellow-100 border-yellow-200 dark:bg-yellow-800/30 dark:border-yellow-700";
      case "error": return "bg-red-100 border-red-200 dark:bg-red-900/30 dark:border-red-700";
      default: return "bg-gray-100 border-gray-200 dark:bg-gray-700/30 dark:border-gray-600";
    }
  };

  const getPriorityColor = (priority?: string) => {
    if(!priority) return "bg-gray-100 text-gray-800";
    switch (priority) {
      case "low": return "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300";
      case "medium": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300";
      case "high": return "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
    }
  };

  const handleInsightClick = (insight: Insight) => {
    setSelectedInsight(selectedInsight?.id === insight.id ? null : insight);
  };

  if (loading && analyzing) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle>AI Analysis in Progress</CardTitle>
          <CardDescription>Our AI is analyzing your network traffic patterns</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Analyzing packets...</span>
              <span>{progress}%</span>
            </div>
            <Progress value={progress} className="h-2" />
            <div className="text-sm text-muted-foreground mt-2">
              {progress < 30
                ? "Extracting packet data and protocol information..."
                : progress < 60
                  ? "Analyzing network flows and connection patterns..."
                  : progress < 90
                    ? "Identifying potential security threats and anomalies..."
                    : "Generating comprehensive security report..."}
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }
  
  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-red-500">Analysis Error</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-red-700">{error}</p>
          <Button onClick={runAnalysis} className="mt-4" disabled={analyzing || loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${analyzing ? "animate-spin" : ""}`} />
            Try Again
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!analysis && !analyzing && !loading) { 
    return (
      <Card>
        <CardHeader>
          <CardTitle>AI Insights</CardTitle>
          <CardDescription>No analysis data available.</CardDescription>
        </CardHeader>
        <CardContent className="text-center py-10">
          <p className="text-muted-foreground">Could not load AI insights for this file.</p>
          <Button onClick={runAnalysis} className="mt-4" disabled={analyzing || loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${analyzing ? "animate-spin" : ""}`} />
            Retry Analysis
          </Button>
        </CardContent>
      </Card>
    );
  }
  
  if (!analysis) {
      return (
          <Card>
              <CardHeader>
                  <CardTitle>AI Insights</CardTitle>
                  <CardDescription>Waiting for analysis results...</CardDescription>
              </CardHeader>
              <CardContent className="flex justify-center items-center h-60">
                  { (loading || analyzing) && <Loader2 className="h-12 w-12 animate-spin text-muted-foreground" /> }
                  { !loading && !analyzing && <p>No analysis data to display.</p>}
              </CardContent>
          </Card>
      );
  }

  // ----- Tampilan utama setelah data analisis diterima -----
  // Ini adalah baris 246 di kode Anda
  return ( 
    <div className="space-y-6"> {/* Ini adalah baris 247 */}
        <> {/* Ini adalah baris 248 */}
          <Card className={`${getSeverityBgColor(analysis.threatLevel)} border-2 shadow-lg`}> {/* Baris 249 */}
            <CardHeader className="pb-4"> {/* Baris 250 */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                <CardTitle className="text-xl md:text-2xl">Threat Analysis Summary</CardTitle>
                <Badge className={`${getSeverityColor(analysis.threatLevel)} px-3 py-1 text-sm`}>
                  {analysis.threatLevel?.charAt(0).toUpperCase() + (analysis.threatLevel?.slice(1) || '')} Threat Level
                </Badge>
              </div>
              <CardDescription className="mt-1">
                Analysis of {(analysis.statistics?.packetsProcessedForStats ?? analysis.statistics?.totalPacketsInFile ?? 0).toLocaleString()} packets
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm md:text-base leading-relaxed">{analysis.summary}</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-6">
                <Card className="bg-background/50 dark:bg-background/20">
                  <CardHeader className="pb-2 pt-4">
                    <CardTitle className="text-base font-semibold flex items-center">
                      <ShieldAlert className="h-5 w-5 mr-2 text-red-500" />
                      Security Findings
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="pb-4">
                    <div className="text-3xl font-bold">{analysis.findings?.length || 0}</div>
                    {analysis.findings && (
                      <div className="text-xs text-muted-foreground mt-1">
                        {analysis.findings.filter((f) => f.severity === "critical").length} critical,{" "}
                        {analysis.findings.filter((f) => f.severity === "high").length} high
                      </div>
                    )}
                  </CardContent>
                </Card>

                {analysis.statistics?.anomalyScore !== undefined && (
                  <Card className="bg-background/50 dark:bg-background/20">
                    <CardHeader className="pb-2 pt-4">
                        <CardTitle className="text-base font-semibold flex items-center">
                        <Activity className="h-5 w-5 mr-2 text-yellow-500" />
                        Anomaly Score
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="pb-4">
                        <div className="text-3xl font-bold">{analysis.statistics.anomalyScore}/100</div>
                        <div className="text-xs text-muted-foreground mt-1">
                        {analysis.statistics.anomalyScore < 30
                            ? "Normal behavior"
                            : analysis.statistics.anomalyScore < 60
                            ? "Some unusual patterns"
                            : "Highly anomalous"}
                        </div>
                    </CardContent>
                  </Card>
                )}

                {analysis.statistics?.topTalkers && analysis.statistics.topTalkers.length > 0 && analysis.statistics.topTalkers[0] && (
                    <Card className="bg-background/50 dark:bg-background/20">
                        <CardHeader className="pb-2 pt-4">
                            <CardTitle className="text-base font-semibold flex items-center">
                                <Users className="h-5 w-5 mr-2 text-blue-500" />
                                Top Talker
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="pb-4">
                            <div className="text-lg font-bold truncate" title={analysis.statistics.topTalkers[0].ip || "Unknown"}>
                                {analysis.statistics.topTalkers[0].ip || "N/A"}
                            </div>
                            <div className="text-xs text-muted-foreground mt-1">
                               {(analysis.statistics.topTalkers[0].packets || 0).toLocaleString()} packets 
                               ({((analysis.statistics.topTalkers[0].bytes || 0) / 1024 / 1024).toFixed(2)} MB)
                            </div>
                        </CardContent>
                    </Card>
                )}
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
            <div className="lg:col-span-2 space-y-6">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-xl flex items-center">
                        <ListChecks className="h-6 w-6 mr-2 text-primary"/> Security Findings
                    </CardTitle>
                    <Button variant="outline" size="sm" onClick={runAnalysis} disabled={analyzing || loading}>
                      <RefreshCw className={`h-4 w-4 mr-2 ${analyzing ? "animate-spin" : ""}`} />
                      Refresh
                    </Button>
                  </div>
                  <CardDescription>AI-detected security issues in your network traffic</CardDescription>
                </CardHeader>
                <CardContent>
                  {analysis.findings?.length > 0 ? (
                    <div className="space-y-4">
                      {analysis.findings.map((finding) => (
                        <Card
                          key={finding.id}
                          className={`${getSeverityBgColor(finding.severity)} border cursor-pointer transition-all hover:shadow-lg ${
                            selectedInsight?.id === finding.id ? "ring-2 ring-primary shadow-xl" : "shadow-md"
                          }`}
                          onClick={() => handleInsightClick(finding)}
                        >
                          <CardHeader className="flex flex-row items-start space-x-3 p-4">
                            <div className={`p-2 rounded-md ${getSeverityBgColor(finding.severity)}`}>
                                {getCategoryIcon(finding.category)}
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center justify-between">
                                <CardTitle className="text-md font-semibold leading-snug">{finding.title}</CardTitle>
                                <Badge className={`${getSeverityColor(finding.severity)} text-xs`}>
                                  {finding.severity?.charAt(0).toUpperCase() + (finding.severity?.slice(1) || '')}
                                </Badge>
                              </div>
                              <CardDescription className="mt-1 text-xs line-clamp-2">{finding.description}</CardDescription>
                            </div>
                          </CardHeader>
                          {selectedInsight?.id === finding.id && (
                             <CardContent className="pt-0 pb-4 px-4 space-y-2 text-sm">
                                <p><strong className="font-medium">Full Description:</strong> {selectedInsight.description}</p>
                                {selectedInsight.detailedAnalysis && (
                                  <p><strong className="font-medium">Detailed Analysis:</strong> {selectedInsight.detailedAnalysis}</p>
                                )}
                                {selectedInsight.affectedHosts && selectedInsight.affectedHosts.length > 0 && (
                                  <div>
                                    <strong className="font-medium">Affected Hosts:</strong>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {selectedInsight.affectedHosts.map((host, index) => (
                                        <Badge key={index} variant="outline" className="font-mono text-xs">{host}</Badge>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                 {selectedInsight.recommendation && (
                                    <p className="mt-2 pt-2 border-t"><strong className="font-medium">Recommendation:</strong> {selectedInsight.recommendation}</p>
                                 )}
                             </CardContent>
                          )}
                        </Card>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-10 text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-4 text-green-500"/>
                      <p>No specific security findings detected by the AI for this file.</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {analysis.recommendations && analysis.recommendations.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-xl flex items-center">
                        <Zap className="h-6 w-6 mr-2 text-primary"/> Recommended Actions
                    </CardTitle>
                    <CardDescription>Steps to address identified security issues</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                        {analysis.recommendations.map((recommendation, index) => (
                        <div key={index} className="p-4 border rounded-lg bg-card flex items-start shadow-sm">
                            <div
                            className={`flex-shrink-0 p-2.5 rounded-full ${
                                recommendation.priority === "high"
                                ? "bg-red-100 dark:bg-red-900/30"
                                : recommendation.priority === "medium"
                                    ? "bg-yellow-100 dark:bg-yellow-800/30"
                                    : "bg-blue-100 dark:bg-blue-800/30"
                            } mr-4`}
                            >
                            {recommendation.priority === "high" ? (
                                <Zap className="h-5 w-5 text-red-600 dark:text-red-400" />
                            ) : recommendation.priority === "medium" ? (
                                <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                            ) : (
                                <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                            )}
                            </div>
                            <div className="flex-1">
                            <div className="flex items-baseline justify-between">
                                <h4 className="font-semibold text-md">{recommendation.title}</h4>
                                <Badge className={`ml-2 ${getPriorityColor(recommendation.priority)} text-xs`}>
                                {recommendation.priority?.charAt(0).toUpperCase() + (recommendation.priority?.slice(1) || '')}
                                </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mt-1 leading-snug">{recommendation.description}</p>
                            </div>
                        </div>
                        ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div> 

            <div className="lg:col-span-1 space-y-6">
              {selectedInsight && ( 
                <Card className="sticky top-6 shadow-lg"> 
                  <CardHeader className={`${getSeverityBgColor(selectedInsight.severity)} border-b`}>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center text-lg">
                        <span className="mr-2">{getCategoryIcon(selectedInsight.category)}</span>
                        {selectedInsight.title}
                      </CardTitle>
                    </div>
                    <CardDescription>
                      Confidence: {selectedInsight.confidence}% | Category:{" "}
                      {selectedInsight.category?.charAt(0).toUpperCase() + (selectedInsight.category?.slice(1) || '')}
                    </CardDescription>
                  </CardHeader>
                  <Tabs defaultValue="details" className="w-full">
                    <CardContent className="p-0"> 
                        <TabsList className="grid w-full grid-cols-3 rounded-none border-b">
                            <TabsTrigger value="details" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Details</TabsTrigger>
                            <TabsTrigger value="timeline" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none" disabled={!selectedInsight.timeline || selectedInsight.timeline.length === 0}>Timeline</TabsTrigger>
                            <TabsTrigger value="mitigation" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Mitigation</TabsTrigger>
                        </TabsList>
                    </CardContent>
                    <ScrollArea className="h-[calc(100vh-20rem)] md:h-auto md:max-h-[500px]"> 
                        <CardContent className="p-4"> 
                            <TabsContent value="details" className="mt-0 space-y-3 text-sm">
                                <p><strong className="font-medium">Full Description:</strong> {selectedInsight.description}</p>
                                {selectedInsight.detailedAnalysis && ( <p><strong className="font-medium">Detailed Analysis:</strong> {selectedInsight.detailedAnalysis}</p> )}
                                {selectedInsight.affectedHosts && selectedInsight.affectedHosts.length > 0 && ( 
                                    <div>
                                        <strong className="font-medium">Affected Hosts:</strong>
                                        <div className="flex flex-wrap gap-1 mt-1">
                                        {selectedInsight.affectedHosts.map((host, index) => (
                                            <Badge key={index} variant="outline" className="font-mono text-xs">{host}</Badge>
                                        ))}
                                        </div>
                                    </div>
                                )}
                                {selectedInsight.relatedPackets && selectedInsight.relatedPackets.length > 0 && ( 
                                     <div>
                                        <strong className="font-medium">Related Packet Samples (Indices):</strong>
                                        <div className="flex flex-wrap gap-1 mt-1">
                                        {selectedInsight.relatedPackets.map((packetId, index) => (
                                            <Badge key={index} variant="secondary" className="text-xs">#{packetId}</Badge>
                                        ))}
                                        </div>
                                    </div>
                                )}
                            </TabsContent>
                            <TabsContent value="timeline" className="mt-0"> 
                                {selectedInsight.timeline && selectedInsight.timeline.length > 0 ? (
                                <div className="relative pl-6 border-l-2 border-muted space-y-4">
                                    {selectedInsight.timeline.map((event, index) => (
                                    <div key={index} className="relative">
                                        <div className="absolute -left-[25px] top-1 w-4 h-4 rounded-full bg-primary"></div>
                                        <div className="text-xs text-muted-foreground">{event.time}</div>
                                        <div className="text-sm mt-0.5">{event.event}</div>
                                    </div>
                                    ))}
                                </div>
                                ) : (
                                <p className="text-sm text-muted-foreground text-center py-4">No specific timeline available for this finding.</p>
                                )}
                            </TabsContent>
                            <TabsContent value="mitigation" className="mt-0 space-y-3 text-sm"> 
                                {selectedInsight.mitigationSteps && selectedInsight.mitigationSteps.length > 0 ? (
                                <>
                                    <div>
                                    <h4 className="font-medium mb-1.5">Recommended Actions:</h4>
                                    <ul className="list-decimal pl-5 space-y-1.5">
                                        {selectedInsight.mitigationSteps.map((step, index) => (
                                        <li key={index}>{step}</li>
                                        ))}
                                    </ul>
                                    </div>
                                    {selectedInsight.recommendation && selectedInsight.recommendation !== selectedInsight.description && (
                                        <p><strong className="font-medium">General Recommendation:</strong> {selectedInsight.recommendation}</p>
                                    )}
                                </>
                                ) : selectedInsight.recommendation ? (
                                    <p><strong className="font-medium">Recommendation:</strong> {selectedInsight.recommendation}</p>
                                ) : (
                                    <p className="text-muted-foreground text-center py-4">No specific mitigation steps provided.</p>
                                )}
                                {selectedInsight.references && selectedInsight.references.length > 0 && (
                                    <div className="mt-4">
                                    <h4 className="font-medium mb-1.5">References:</h4>
                                    <ul className="space-y-1">
                                        {selectedInsight.references.map((ref, index) => (
                                        <li key={index}>
                                            <a
                                            href={ref.url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-blue-600 hover:underline flex items-center text-xs"
                                            >
                                            {ref.title} <ExternalLink className="h-3 w-3 ml-1"/>
                                            </a>
                                        </li>
                                        ))}
                                    </ul>
                                    </div>
                                )}
                            </TabsContent>
                        </CardContent>
                    </ScrollArea>
                  </Tabs>
                </Card>
              )}

              {(!selectedInsight && analysis.findings && analysis.findings.length > 0) && (
                 <Card className="sticky top-6">
                    <CardHeader>
                        <CardTitle className="flex items-center"><Info className="mr-2 h-5 w-5 text-blue-500"/>Finding Details</CardTitle>
                        <CardDescription>Select a finding from the list on the left to view its detailed information here.</CardDescription>
                    </CardHeader>
                    <CardContent className="text-center py-10 text-muted-foreground">
                        <Search className="h-10 w-10 mx-auto mb-3 text-gray-400" />
                        <p>Click on a security finding to see details.</p>
                    </CardContent>
                 </Card>
              )}
            
              {analysis.iocs && analysis.iocs.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-xl flex items-center">
                        <FileText className="h-6 w-6 mr-2 text-primary"/> Indicators of Compromise
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                     <IOCList iocs={analysis.iocs} />
                  </CardContent>
                </Card>
              )}

              {analysis.timeline && analysis.timeline.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-xl flex items-center">
                        <History className="h-6 w-6 mr-2 text-primary"/> Overall Activity Timeline
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="max-h-[300px] pr-3">
                        <div className="relative pl-6 border-l-2 border-muted space-y-4">
                            {analysis.timeline.map((event, index) => ( 
                                <div key={index} className="relative">
                                    <div
                                    className={`absolute -left-[25px] top-1 w-4 h-4 rounded-full ${
                                        event.severity === "error"
                                        ? "bg-red-500"
                                        : event.severity === "warning"
                                            ? "bg-yellow-500"
                                            : "bg-blue-500"
                                    }`}
                                    ></div>
                                    <div className="text-xs text-muted-foreground">{event.time}</div>
                                    <div
                                    className={`text-sm mt-0.5 p-2 rounded-md ${getTimelineSeverityColor(event.severity)} border`}
                                    >
                                    {event.event}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              )}

              {analysis.statistics && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-xl flex items-center">
                        <BarChart3 className="h-6 w-6 mr-2 text-primary"/> Traffic Statistics
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                        <div>
                        <h4 className="text-sm font-medium mb-2">Protocol Distribution</h4>
                        <div className="space-y-2">
                            {Object.entries(analysis.statistics.protocols || {}).map(([protocol, count]) => { // Tambah check protocols
                            if (count === 0 && protocol.toUpperCase() !== 'UNKNOWN_L3' && protocol.toUpperCase() !== 'UNKNOWNL4') return null; 
                            const denominator = analysis.statistics?.packetsProcessedForStats ?? analysis.statistics?.totalPacketsInFile ?? 1;
                            const percentage = Math.round((count / (denominator === 0 ? 1 : denominator)) * 100);
                            return (
                                <div key={protocol} className="space-y-1">
                                <div className="flex justify-between text-sm">
                                    <span>{protocol}</span>
                                    <span>
                                    {(count || 0).toLocaleString()} ({percentage}%)
                                    </span>
                                </div>
                                <Progress value={percentage} className="h-2" />
                                </div>
                            );
                            })}
                        </div>
                        </div>

                        {analysis.statistics.topTalkers && analysis.statistics.topTalkers.length > 0 && analysis.statistics.topTalkers[0] && (
                        <div>
                            <h4 className="text-sm font-medium mb-2">Top Talkers</h4>
                            <div className="space-y-2">
                            {analysis.statistics.topTalkers.map((talker, index) => (
                                <div key={index} className="flex justify-between items-center p-2 bg-muted/50 rounded-md">
                                <div className="flex items-center min-w-0"> {/* Tambah min-w-0 untuk truncate */}
                                    <div
                                    className={`w-2 h-8 rounded-sm mr-2 flex-shrink-0 ${
                                        index === 0 ? "bg-red-500" : index === 1 ? "bg-orange-500" : "bg-yellow-500"
                                    }`}
                                    ></div>
                                    <div className="min-w-0"> {/* Tambah min-w-0 untuk truncate */}
                                      <div className="text-sm font-medium truncate" title={talker.ip}>{talker.ip || "N/A"}</div>
                                      <div className="text-xs text-muted-foreground">
                                          {(talker.packets || 0).toLocaleString()} packets
                                      </div>
                                    </div>
                                </div>
                                <div className="text-sm whitespace-nowrap pl-2">{((talker.bytes || 0) / 1024 / 1024).toFixed(2)} MB</div>
                                </div>
                            ))}
                            </div>
                        </div>
                        )}
                    </div>
                   </CardContent>
                </Card>
              )}
            </div> 
          </div>
        </>
    </div>
  );
}
