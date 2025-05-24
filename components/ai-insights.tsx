"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2, AlertTriangle, Shield, Activity, Network, FileWarning, RefreshCw, Zap, Search, ExternalLink, EyeOff } from "lucide-react"; // Tambahkan EyeOff
import { IOCList } from "@/components/ioc-list";

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

// --- PERBAIKAN INTERFACE AIAnalysis ---
interface AIAnalysis {
  summary: string;
  threatLevel: "low" | "medium" | "high" | "critical";
  findings: Insight[];
  statistics: {
    totalPacketsInFile: number;         // Sesuai dengan output AI
    packetsProcessedForStats?: number;  // Sesuai dengan output AI, buat opsional jika AI bisa tidak mengirimkannya
    // analyzedPackets?: number;        // Hapus atau sesuaikan jika ini field lama yang tidak terpakai
    protocols: { [key: string]: number; };
    topTalkers?: { 
        ip: string; 
        packets: number; 
        bytes: number;
        // Tambahkan field ini jika ada di data parsing Anda dan dikirim ke AI & kembali dari AI
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
// --- AKHIR PERBAIKAN INTERFACE ---

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
        setAnalysis(data.analysis);
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

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low": return "bg-blue-100 text-blue-800";
      case "medium": return "bg-yellow-100 text-yellow-800";
      case "high": return "bg-orange-100 text-orange-800";
      case "critical": return "bg-red-100 text-red-800";
      default: return "bg-gray-100 text-gray-800";
    }
  };

  const getSeverityBgColor = (severity: string) => {
    switch (severity) {
      case "low": return "bg-blue-50 border-blue-200";
      case "medium": return "bg-yellow-50 border-yellow-200";
      case "high": return "bg-orange-50 border-orange-200";
      case "critical": return "bg-red-50 border-red-200";
      default: return "bg-gray-50 border-gray-200";
    }
  };
  
  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "malware": return <Shield className="h-5 w-5" />;
      case "anomaly": return <Activity className="h-5 w-5" />;
      case "exfiltration": return <Network className="h-5 w-5" />;
      case "vulnerability": return <FileWarning className="h-5 w-5" />;
      case "reconnaissance": return <Search className="h-5 w-5" />;
      case "policy-violation": return <FileWarning className="h-5 w-5 text-orange-500" />;
      case "benign-but-noteworthy": return <Activity className="h-5 w-5 text-blue-500" />;
      default: return <AlertTriangle className="h-5 w-5" />;
    }
  };

  const getTimelineSeverityColor = (severity: string) => {
    switch (severity) {
      case "info": return "bg-blue-100 border-blue-200 dark:bg-blue-900/30 dark:border-blue-700";
      case "warning": return "bg-yellow-100 border-yellow-200 dark:bg-yellow-800/30 dark:border-yellow-700";
      case "error": return "bg-red-100 border-red-200 dark:bg-red-900/30 dark:border-red-700";
      default: return "bg-gray-100 border-gray-200 dark:bg-gray-700/30 dark:border-gray-600";
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "low": return "bg-blue-100 text-blue-800";
      case "medium": return "bg-yellow-100 text-yellow-800";
      case "high": return "bg-red-100 text-red-800";
      default: return "bg-gray-100 text-gray-800";
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
  return (
    <div className="space-y-6">
        <>
          <Card className={`${getSeverityBgColor(analysis.threatLevel)} border-2`}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle>Threat Analysis Summary</CardTitle>
                <Badge className={getSeverityColor(analysis.threatLevel)}>
                  {analysis.threatLevel.charAt(0).toUpperCase() + analysis.threatLevel.slice(1)} Threat Level
                </Badge>
              </div>
              <CardDescription>
                {/* --- PERBAIKAN AKSES FIELD --- */}
                Analysis of {(analysis.statistics.packetsProcessedForStats ?? analysis.statistics.totalPacketsInFile ?? 0).toLocaleString()} packets
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm md:text-base">{analysis.summary}</p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                <div className="bg-white/70 dark:bg-black/30 p-3 rounded-lg border">
                  <div className="flex items-center text-sm font-medium">
                    <Shield className="h-4 w-4 mr-2 text-red-500" />
                    Security Findings
                  </div>
                  <div className="text-2xl font-bold mt-1">{analysis.findings?.length || 0}</div>
                  {analysis.findings && (
                    <div className="text-xs text-muted-foreground mt-1">
                      {analysis.findings.filter((f) => f.severity === "critical").length} critical,{" "}
                      {analysis.findings.filter((f) => f.severity === "high").length} high
                    </div>
                  )}
                </div>

                {analysis.statistics.anomalyScore !== undefined && (
                  <div className="bg-white/70 dark:bg-black/30 p-3 rounded-lg border">
                    <div className="flex items-center text-sm font-medium">
                      <Activity className="h-4 w-4 mr-2 text-yellow-500" />
                      Anomaly Score
                    </div>
                    <div className="text-2xl font-bold mt-1">{analysis.statistics.anomalyScore}/100</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {analysis.statistics.anomalyScore < 30
                        ? "Normal network behavior"
                        : analysis.statistics.anomalyScore < 60
                          ? "Some unusual patterns"
                          : "Highly anomalous traffic"}
                    </div>
                  </div>
                )}

                {analysis.statistics.topTalkers && analysis.statistics.topTalkers.length > 0 && analysis.statistics.topTalkers[0] && (
                    <div className="bg-white/70 dark:bg-black/30 p-3 rounded-lg border">
                        <div className="flex items-center text-sm font-medium">
                        <Network className="h-4 w-4 mr-2 text-blue-500" />
                        Top Talker
                        </div>
                        <div className="text-xl font-bold mt-1 truncate" title={analysis.statistics.topTalkers[0].ip || "Unknown"}>
                            {analysis.statistics.topTalkers[0].ip || "Unknown"}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                           {/* Pastikan packets dan bytes ada sebelum memanggil toLocaleString/toFixed */}
                           {analysis.statistics.topTalkers[0].packets?.toLocaleString() || '0'} packets (
                           {((analysis.statistics.topTalkers[0].bytes || 0) / 1024 / 1024).toFixed(2)} MB)
                        </div>
                    </div>
                )}
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <Card>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle>Security Findings</CardTitle>
                    <Button variant="outline" size="sm" onClick={runAnalysis} disabled={analyzing || loading}>
                      <RefreshCw className={`h-4 w-4 mr-2 ${analyzing ? "animate-spin" : ""}`} />
                      Refresh Analysis
                    </Button>
                  </div>
                  <CardDescription>AI-detected security issues in your network traffic</CardDescription>
                </CardHeader>
                <CardContent>
                  {analysis.findings?.length > 0 ? (
                    <div className="space-y-4">
                      {analysis.findings.map((finding) => (
                        <Alert
                          key={finding.id}
                          variant="default"
                          className={`${getSeverityBgColor(finding.severity)} border cursor-pointer transition-shadow hover:shadow-md ${
                            selectedInsight?.id === finding.id ? "ring-2 ring-primary shadow-lg" : ""
                          }`}
                          onClick={() => handleInsightClick(finding)}
                        >
                          <div className="flex items-start">
                            <span className="pt-0.5">{getCategoryIcon(finding.category)}</span>
                            <div className="ml-3 flex-1">
                              <div className="flex items-center justify-between">
                                <AlertTitle className="text-base font-semibold">{finding.title}</AlertTitle>
                                <Badge className={getSeverityColor(finding.severity)}>
                                  {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
                                </Badge>
                              </div>
                              <AlertDescription className="mt-1 text-sm">{finding.description}</AlertDescription>
                              <div className="mt-2 flex items-center text-xs text-muted-foreground">
                                <span>AI Confidence: {finding.confidence}%</span>
                                <Progress value={finding.confidence} className="h-1.5 ml-2 w-24" />
                              </div>
                            </div>
                          </div>
                        </Alert>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-10">
                      <Shield className="h-12 w-12 mx-auto mb-4 text-green-500"/>
                      <p className="text-muted-foreground">No specific security findings detected by the AI for this file.</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {analysis.recommendations && analysis.recommendations.length > 0 && (
                <Card className="mt-6">
                  <CardHeader className="pb-2">
                    <CardTitle>Recommended Actions</CardTitle>
                    <CardDescription>Steps to address identified security issues</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                        {analysis.recommendations.map((recommendation, index) => (
                        <div key={index} className="p-4 border rounded-lg bg-card flex items-start">
                            <div
                            className={`p-2 rounded-full ${
                                recommendation.priority === "high"
                                ? "bg-red-100 dark:bg-red-900/30"
                                : recommendation.priority === "medium"
                                    ? "bg-yellow-100 dark:bg-yellow-800/30"
                                    : "bg-blue-100 dark:bg-blue-800/30"
                            } mr-3`}
                            >
                            {recommendation.priority === "high" ? (
                                <Zap className="h-5 w-5 text-red-600 dark:text-red-400" />
                            ) : recommendation.priority === "medium" ? (
                                <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                            ) : (
                                <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                            )}
                            </div>
                            <div>
                            <div className="flex items-center">
                                <h4 className="font-medium">{recommendation.title}</h4>
                                <Badge className={`ml-2 ${getPriorityColor(recommendation.priority)}`}>
                                {recommendation.priority.charAt(0).toUpperCase() + recommendation.priority.slice(1)}
                                </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mt-1">{recommendation.description}</p>
                            </div>
                        </div>
                        ))}
                    </div>
                  </CardContent>
                </Card>
              )}
              
              {analysis.iocs && analysis.iocs.length > 0 && (
                <Card className="mt-6">
                  <CardHeader className="pb-2">
                    <CardTitle>Indicators of Compromise</CardTitle>
                    <CardDescription>Potential IOCs extracted from network traffic</CardDescription>
                  </CardHeader>
                  <CardContent>
                     <IOCList iocs={analysis.iocs} />
                  </CardContent>
                </Card>
              )}
            </div>

            <div className="space-y-6">
              {selectedInsight ? (
                <Card className="sticky top-4">
                  <CardHeader className={`${getSeverityBgColor(selectedInsight.severity)} border-b`}>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center text-lg">
                        <span className="mr-2">{getCategoryIcon(selectedInsight.category)}</span>
                        {selectedInsight.title}
                      </CardTitle>
                      <Badge className={getSeverityColor(selectedInsight.severity)}>
                        {selectedInsight.severity.charAt(0).toUpperCase() + selectedInsight.severity.slice(1)}
                      </Badge>
                    </div>
                    <CardDescription>
                      Confidence: {selectedInsight.confidence}% | Category:{" "}
                      {selectedInsight.category.charAt(0).toUpperCase() + selectedInsight.category.slice(1)}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-4">
                    <Tabs defaultValue="details">
                      <TabsList className="grid w-full grid-cols-3">
                        <TabsTrigger value="details">Details</TabsTrigger>
                        <TabsTrigger value="timeline" disabled={!selectedInsight.timeline || selectedInsight.timeline.length === 0}>Timeline</TabsTrigger>
                        <TabsTrigger value="mitigation">Mitigation</TabsTrigger>
                      </TabsList>
                      <TabsContent value="details" className="pt-4 space-y-3 text-sm">
                          <p><strong className="font-medium">Description:</strong> {selectedInsight.description}</p>
                          {selectedInsight.detailedAnalysis && (
                            <p><strong className="font-medium">Detailed Analysis:</strong> {selectedInsight.detailedAnalysis}</p>
                          )}
                          {selectedInsight.affectedHosts && selectedInsight.affectedHosts.length > 0 && (
                            <div>
                              <strong className="font-medium">Affected Hosts:</strong>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {selectedInsight.affectedHosts.map((host, index) => (
                                  <Badge key={index} variant="outline" className="font-mono">{host}</Badge>
                                ))}
                              </div>
                            </div>
                          )}
                          {selectedInsight.relatedPackets && selectedInsight.relatedPackets.length > 0 && (
                            <div>
                              <strong className="font-medium">Related Packet Samples (Indices):</strong>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {selectedInsight.relatedPackets.map((packetId, index) => (
                                  <Badge key={index} variant="secondary">#{packetId}</Badge>
                                ))}
                              </div>
                            </div>
                          )}
                      </TabsContent>
                      <TabsContent value="timeline" className="pt-4">
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
                      <TabsContent value="mitigation" className="pt-4 space-y-3 text-sm">
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
                            <p className="text-muted-foreground text-center py-4">No specific mitigation steps provided for this finding.</p>
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
                                    className="text-blue-600 hover:underline flex items-center"
                                    >
                                    {ref.title} <ExternalLink className="h-3 w-3 ml-1"/>
                                    </a>
                                </li>
                                ))}
                            </ul>
                            </div>
                        )}
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </Card>
              ) : (
                <Card className="sticky top-4">
                  <CardHeader>
                    <CardTitle>Finding Details</CardTitle>
                    <CardDescription>Select a finding from the list to view detailed information.</CardDescription>
                  </CardHeader>
                  <CardContent className="text-center py-8 text-muted-foreground">
                    <Search className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                    <p>Click on a security finding to see its details here.</p>
                  </CardContent>
                </Card>
              )}

              {analysis.timeline && analysis.timeline.length > 0 && (
                <Card className="mt-6">
                  <CardHeader className="pb-2">
                    <CardTitle>Overall Activity Timeline</CardTitle>
                    <CardDescription>Chronological view of significant events in the capture</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="relative pl-6 border-l-2 border-muted space-y-4 max-h-[300px] overflow-y-auto pr-2">
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
                  </CardContent>
                </Card>
              )}

              {analysis.statistics && (
                <Card className="mt-6">
                  <CardHeader className="pb-2">
                    <CardTitle>Traffic Statistics Overview</CardTitle>
                    <CardDescription>Key metrics from the analyzed PCAP data</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                        <div>
                        <h4 className="text-sm font-medium mb-2">Protocol Distribution</h4>
                        <div className="space-y-2">
                            {Object.entries(analysis.statistics.protocols).map(([protocol, count]) => {
                            if (count === 0 && protocol !== 'UNKNOWN_L3') return null; // Jangan tampilkan jika count 0, kecuali UNKNOWN_L3 jika perlu
                            // --- PERBAIKAN DENOMINATOR PERSENTASE ---
                            const denominator = analysis.statistics.packetsProcessedForStats ?? analysis.statistics.totalPacketsInFile ?? 1; // Hindari pembagian dengan 0
                            const percentage = Math.round((count / (denominator === 0 ? 1 : denominator)) * 100);
                            return (
                                <div key={protocol} className="space-y-1">
                                <div className="flex justify-between text-sm">
                                    <span>{protocol}</span>
                                    <span>
                                    {count.toLocaleString()} ({percentage}%)
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
                                <div className="flex items-center">
                                    <div
                                    className={`w-2 h-8 rounded-sm mr-2 ${
                                        index === 0 ? "bg-red-500" : index === 1 ? "bg-orange-500" : "bg-yellow-500"
                                    }`}
                                    ></div>
                                    <div>
                                    <div className="text-sm font-medium truncate" title={talker.ip}>{talker.ip}</div>
                                    <div className="text-xs text-muted-foreground">
                                        {(talker.packets || 0).toLocaleString()} packets
                                    </div>
                                    </div>
                                </div>
                                <div className="text-sm whitespace-nowrap">{((talker.bytes || 0) / 1024 / 1024).toFixed(2)} MB</div>
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
