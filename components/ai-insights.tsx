"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2, AlertTriangle, Shield, Activity, Network, FileWarning, RefreshCw, Zap, Search, ExternalLink, EyeOff, ListChecks, History, ShieldAlert, Info, Users, FileText, BarChart3, Route } from "lucide-react";
import { IOCList } from "@/components/ioc-list";
import { ScrollArea } from "@/components/ui/scroll-area"; // Untuk daftar yang panjang

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

  // ... (fungsi runAnalysis, getSeverityColor, dll. tetap sama seperti versi terakhir)
  // Pastikan fungsi-fungsi helper ini ada dan benar
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
        // Lakukan normalisasi atau pastikan field yang diharapkan ada
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

  const getSeverityColor = (severity?: string) => { // Tambahkan pengecekan undefined
    if (!severity) return "bg-gray-100 text-gray-800";
    switch (severity) {
      case "low": return "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300";
      case "medium": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300";
      case "high": return "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300";
      case "critical": return "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";
    }
  };

  const getSeverityBgColor = (severity?: string) => { // Tambahkan pengecekan undefined
    if (!severity) return "bg-gray-50 border-gray-200 dark:bg-gray-800 dark:border-gray-700";
    switch (severity) {
      case "low": return "bg-blue-50 border-blue-200 dark:bg-blue-900/30 dark:border-blue-800";
      case "medium": return "bg-yellow-50 border-yellow-200 dark:bg-yellow-900/30 dark:border-yellow-800";
      case "high": return "bg-orange-50 border-orange-200 dark:bg-orange-900/30 dark:border-orange-800";
      case "critical": return "bg-red-50 border-red-200 dark:bg-red-900/30 dark:border-red-800";
      default: return "bg-gray-50 border-gray-200 dark:bg-gray-800 dark:border-gray-700";
    }
  };
  
  const getCategoryIcon = (category?: string) => { // Tambahkan pengecekan undefined
    if(!category) return <Info className="h-5 w-5 text-gray-500" />;
    switch (category) {
      case "malware": return <ShieldAlert className="h-5 w-5 text-red-500" />;
      case "anomaly": return <Activity className="h-5 w-5 text-yellow-500" />;
      case "exfiltration": return <Route className="h-5 w-5 text-purple-500" />; // Route icon bisa lebih cocok
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
  // --- Akhir Fungsi Helper ---

  if (loading && analyzing) { /* ... (kode loading tetap sama) ... */ }
  if (error) { /* ... (kode error tetap sama) ... */ }
  if (!analysis && !analyzing && !loading) { /* ... (kode no analysis tetap sama) ... */ }
  if (!analysis) { /* ... (kode !analysis tetap sama) ... */ }

  // ----- Tampilan utama setelah data analisis diterima -----
  return (
    <div className="space-y-6">
        <>
          <Card className={`${getSeverityBgColor(analysis.threatLevel)} border-2 shadow-lg`}>
            <CardHeader className="pb-4"> {/* Tambah padding bawah */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                <CardTitle className="text-xl md:text-2xl">Threat Analysis Summary</CardTitle>
                <Badge className={`${getSeverityColor(analysis.threatLevel)} px-3 py-1 text-sm`}>
                  {analysis.threatLevel?.charAt(0).toUpperCase() + analysis.threatLevel?.slice(1)} Threat Level
                </Badge>
              </div>
              <CardDescription className="mt-1">
                Analysis of {(analysis.statistics?.packetsProcessedForStats ?? analysis.statistics?.totalPacketsInFile ?? 0).toLocaleString()} packets
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm md:text-base leading-relaxed">{analysis.summary}</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-6"> {/* Responsive grid */}
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
                                <Users className="h-5 w-5 mr-2 text-blue-500" /> {/* Icon Users untuk Top Talker */}
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
            <div className="lg:col-span-2 space-y-6"> {/* Tambah space-y-6 di sini */}
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
                        <Card // Menggunakan Card untuk setiap finding agar lebih terstruktur
                          key={finding.id}
                          className={`${getSeverityBgColor(finding.severity)} border cursor-pointer transition-all hover:shadow-lg ${
                            selectedInsight?.id === finding.id ? "ring-2 ring-primary shadow-xl" : "shadow-md"
                          }`}
                          onClick={() => handleInsightClick(finding)}
                        >
                          <CardHeader className="flex flex-row items-start space-x-3 p-4">
                            <div className={`p-2 rounded-md ${getSeverityBgColor(finding.severity)}`}> {/* Lingkaran ikon lebih soft */}
                                {getCategoryIcon(finding.category)}
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center justify-between">
                                <CardTitle className="text-md font-semibold leading-snug">{finding.title}</CardTitle>
                                <Badge className={`${getSeverityColor(finding.severity)} text-xs`}>
                                  {finding.severity?.charAt(0).toUpperCase() + finding.severity?.slice(1)}
                                </Badge>
                              </div>
                              <CardDescription className="mt-1 text-xs line-clamp-2">{finding.description}</CardDescription> {/* Line clamp untuk deskripsi singkat */}
                            </div>
                          </CardHeader>
                          {selectedInsight?.id === finding.id && ( // Tampilkan detail di bawah jika terpilih
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
                                {recommendation.priority?.charAt(0).toUpperCase() + recommendation.priority?.slice(1)}
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
            </div> {/* Akhir lg:col-span-2 */}

            {/* Kolom Kanan untuk Detail Finding Terpilih, IOC, Timeline, Statistik */}
            <div className="lg:col-span-1 space-y-6">
              {selectedInsight && ( // Pindahkan SelectedInsight Detail Card ke sini
                <Card className="sticky top-6 shadow-lg"> {/* Buat sticky */}
                  <CardHeader className={`${getSeverityBgColor(selectedInsight.severity)} border-b`}>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center text-lg">
                        <span className="mr-2">{getCategoryIcon(selectedInsight.category)}</span>
                        {selectedInsight.title}
                      </CardTitle>
                    </div>
                    <CardDescription>
                      Confidence: {selectedInsight.confidence}% | Category:{" "}
                      {selectedInsight.category?.charAt(0).toUpperCase() + selectedInsight.category?.slice(1)}
                    </CardDescription>
                  </CardHeader>
                  <Tabs defaultValue="details" className="w-full">
                    <CardContent className="p-0"> {/* Hapus padding default CardContent */}
                        <TabsList className="grid w-full grid-cols-3 rounded-none border-b">
                            <TabsTrigger value="details" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Details</TabsTrigger>
                            <TabsTrigger value="timeline" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none" disabled={!selectedInsight.timeline || selectedInsight.timeline.length === 0}>Timeline</TabsTrigger>
                            <TabsTrigger value="mitigation" className="py-3 data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none">Mitigation</TabsTrigger>
                        </TabsList>
                    </CardContent>
                    <ScrollArea className="h-[calc(100vh-20rem)] md:h-auto md:max-h-[500px]"> {/* Atur tinggi untuk scroll */}
                        <CardContent className="p-4"> {/* Tambah padding lagi di sini */}
                            <TabsContent value="details" className="mt-0 space-y-3 text-sm">
                                <p><strong className="font-medium">Full Description:</strong> {selectedInsight.description}</p>
                                {selectedInsight.detailedAnalysis && ( <p><strong className="font-medium">Detailed Analysis:</strong> {selectedInsight.detailedAnalysis}</p> )}
                                {selectedInsight.affectedHosts && selectedInsight.affectedHosts.length > 0 && ( /* ... */ )}
                                {selectedInsight.relatedPackets && selectedInsight.relatedPackets.length > 0 && ( /* ... */ )}
                            </TabsContent>
                            <TabsContent value="timeline" className="mt-0"> {/* ... (timeline content tetap sama) ... */}</TabsContent>
                            <TabsContent value="mitigation" className="mt-0 space-y-3 text-sm"> {/* ... (mitigation content tetap sama) ... */}</TabsContent>
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
                            {analysis.timeline.map((event, index) => ( /* ... (timeline event mapping tetap sama) ... */ ))}
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
                  <CardContent> {/* ... (statistik content tetap sama) ... */} </CardContent>
                </Card>
              )}
            </div> {/* Akhir lg:col-span-1 */}
          </div>
        </>
    </div>
  );
}
