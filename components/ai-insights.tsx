"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Loader2, AlertTriangle, Shield, Activity, Network, FileWarning, RefreshCw, Zap, Search } from "lucide-react"
import { IOCList } from "@/components/ioc-list"

interface AIInsightsProps {
  analysisId: string
}

interface Insight {
  id: string
  title: string
  description: string
  severity: "low" | "medium" | "high" | "critical"
  confidence: number
  recommendation?: string
  category: "malware" | "anomaly" | "exfiltration" | "vulnerability" | "reconnaissance"
  affectedHosts?: string[]
  detailedAnalysis?: string
  relatedPackets?: number[]
  timeline?: {
    time: string
    event: string
  }[]
  mitigationSteps?: string[]
  references?: {
    title: string
    url: string
  }[]
}

interface AIAnalysis {
  summary: string
  threatLevel: "low" | "medium" | "high" | "critical"
  findings: Insight[]
  statistics: {
    totalPackets: number
    analyzedPackets: number
    protocols: {
      [key: string]: number
    }
    topTalkers: {
      ip: string
      packets: number
      bytes: number
    }[]
    anomalyScore: number
  }
  timeline: {
    time: string
    event: string
    severity: "info" | "warning" | "error"
  }[]
  recommendations: {
    title: string
    description: string
    priority: "low" | "medium" | "high"
  }[]
  iocs?: {
    type: "ip" | "domain" | "url" | "hash"
    value: string
    context: string
    confidence: number
  }[]
}

export function AIInsights({ analysisId }: AIInsightsProps) {
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(true)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [selectedInsight, setSelectedInsight] = useState<Insight | null>(null)

  const runAnalysis = async () => {
    if (!analysisId) {
      setError("Invalid analysis ID")
      setLoading(false)
      setAnalyzing(false)
      return
    }

    setLoading(true)
    setAnalyzing(true)
    setProgress(0)
    setError(null)
    setSelectedInsight(null)

    // Simulate AI analysis progress
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(progressInterval)
          setAnalyzing(false)
          return 100
        }
        return prev + 1
      })
    }, 100)

    try {
      // For demo purposes, we'll use mock data
      await new Promise((resolve) => setTimeout(resolve, 10000))

      // Mock analysis data with more detailed insights
      const mockAnalysis: AIAnalysis = {
        summary:
          "Analysis of the PCAP file revealed several significant security concerns including potential data exfiltration, command and control communication, and reconnaissance activity. The network shows signs of compromise with multiple hosts exhibiting suspicious behavior patterns consistent with advanced persistent threat (APT) activity.",
        threatLevel: "high",
        findings: [
          {
            id: "finding-1",
            title: "Command & Control Communication",
            description:
              "Host 192.168.1.105 is communicating with a known malicious IP address (203.0.113.42) using an encrypted channel with unusual timing patterns. The communication exhibits beaconing characteristics typical of command and control infrastructure.",
            severity: "critical",
            confidence: 92,
            recommendation:
              "Isolate host 192.168.1.105 immediately and perform a full forensic analysis. Block all communication with 203.0.113.42 at the firewall level.",
            category: "malware",
            affectedHosts: ["192.168.1.105"],
            detailedAnalysis:
              "The communication pattern shows regular beaconing every 300 seconds with small encrypted packets (typically 164 bytes) followed by larger response packets (1420 bytes). This pattern is consistent with the Cobalt Strike C2 framework. The destination IP 203.0.113.42 has been associated with APT29 infrastructure in recent threat intelligence reports.",
            relatedPackets: [42, 56, 78, 103, 128],
            timeline: [
              { time: "10:15:22", event: "Initial connection established" },
              { time: "10:15:24", event: "Encrypted handshake completed" },
              { time: "10:20:22", event: "First beacon sent" },
              { time: "10:25:22", event: "Second beacon with larger response" },
            ],
            mitigationSteps: [
              "Isolate affected host from the network",
              "Capture memory dump before powering down",
              "Block C2 IP at firewall and DNS levels",
              "Scan all systems for similar indicators of compromise",
              "Reset credentials for all accounts accessed from the compromised host",
            ],
            references: [
              {
                title: "MITRE ATT&CK: Command and Control",
                url: "https://attack.mitre.org/tactics/TA0011/",
              },
              {
                title: "APT29 Threat Report",
                url: "https://example.com/threat-reports/apt29",
              },
            ],
          },
          {
            id: "finding-2",
            title: "Data Exfiltration via DNS Tunneling",
            description:
              "Unusual DNS queries detected from host 192.168.1.106 containing encoded data payloads. The queries are directed to suspicious domain names with high entropy values, indicating potential data exfiltration via DNS tunneling.",
            severity: "high",
            confidence: 87,
            recommendation:
              "Implement DNS monitoring and filtering. Investigate host 192.168.1.106 for compromise and determine what data may have been exfiltrated.",
            category: "exfiltration",
            affectedHosts: ["192.168.1.106"],
            detailedAnalysis:
              "The DNS queries contain Base64-encoded data in subdomain names, with each query containing approximately 40 bytes of encoded data. The destination domain uses fast-flux techniques with multiple IP addresses. Analysis of the encoded data suggests it may contain authentication credentials and document metadata.",
            relatedPackets: [145, 146, 147, 152, 158, 163],
            timeline: [
              { time: "11:32:15", event: "First suspicious DNS query" },
              { time: "11:32:18", event: "Series of 12 sequential queries with encoded data" },
              { time: "11:45:22", event: "Second batch of encoded DNS queries" },
            ],
            mitigationSteps: [
              "Implement DNS request filtering and monitoring",
              "Block outbound DNS except through authorized DNS servers",
              "Deploy DNS security solutions that can detect tunneling",
              "Investigate the compromised host for malware",
              "Determine what sensitive data may have been accessed",
            ],
          },
          {
            id: "finding-3",
            title: "Internal Network Scanning Activity",
            description:
              "Host 192.168.1.107 performed sequential port scanning against multiple internal hosts. The scanning pattern suggests reconnaissance activity targeting SSH, RDP, and web services.",
            severity: "medium",
            confidence: 94,
            recommendation:
              "Investigate host 192.168.1.107 for compromise or unauthorized scanning tools. Implement network segmentation and internal firewall rules.",
            category: "reconnaissance",
            affectedHosts: ["192.168.1.107", "192.168.1.1", "192.168.1.10", "192.168.1.20"],
            detailedAnalysis:
              "The scanning activity targeted ports 22 (SSH), 3389 (RDP), 80 (HTTP), and 443 (HTTPS) across the 192.168.1.0/24 subnet. The scan used TCP SYN packets with a consistent TTL value of 64, suggesting the scanning originated from a Linux-based system. The timing pattern indicates the use of a stealth scanning technique designed to evade detection.",
            relatedPackets: [203, 204, 205, 206, 207, 208, 209, 210],
          },
          {
            id: "finding-4",
            title: "TLS Certificate Validation Failure",
            description:
              "Multiple TLS certificate validation failures detected when connecting to internal server 192.168.1.20. This could indicate a man-in-the-middle attack or misconfigured server.",
            severity: "medium",
            confidence: 78,
            recommendation:
              "Verify the TLS certificate configuration on server 192.168.1.20. Investigate potential man-in-the-middle attacks.",
            category: "vulnerability",
            affectedHosts: ["192.168.1.20"],
          },
          {
            id: "finding-5",
            title: "Suspicious PowerShell Command Execution",
            description:
              "HTTP traffic to internal server contains evidence of PowerShell command execution with obfuscated parameters. The commands appear to be downloading and executing additional payloads.",
            severity: "high",
            confidence: 85,
            recommendation:
              "Investigate the affected server for compromise. Implement PowerShell logging and constrained language mode.",
            category: "malware",
            affectedHosts: ["192.168.1.15"],
          },
        ],
        statistics: {
          totalPackets: 15243,
          analyzedPackets: 15243,
          protocols: {
            TCP: 10567,
            UDP: 3245,
            HTTP: 876,
            HTTPS: 432,
            DNS: 123,
          },
          topTalkers: [
            { ip: "192.168.1.105", packets: 3245, bytes: 4562345 },
            { ip: "192.168.1.106", packets: 2456, bytes: 3452678 },
            { ip: "203.0.113.42", packets: 1234, bytes: 2345678 },
          ],
          anomalyScore: 78,
        },
        timeline: [
          { time: "10:15:22", event: "Initial C2 communication detected", severity: "error" },
          { time: "10:32:15", event: "DNS tunneling activity began", severity: "error" },
          { time: "10:45:30", event: "Internal port scanning detected", severity: "warning" },
          { time: "11:02:45", event: "TLS certificate validation failures", severity: "warning" },
          { time: "11:15:22", event: "PowerShell command execution detected", severity: "error" },
        ],
        recommendations: [
          {
            title: "Isolate Compromised Hosts",
            description:
              "Immediately isolate hosts 192.168.1.105 and 192.168.1.106 from the network to prevent further data exfiltration and command execution.",
            priority: "high",
          },
          {
            title: "Implement DNS Monitoring",
            description:
              "Deploy DNS monitoring and filtering solutions to detect and block DNS tunneling and communication with malicious domains.",
            priority: "high",
          },
          {
            title: "Enhance Network Segmentation",
            description:
              "Implement stricter network segmentation to limit lateral movement and unauthorized scanning within the internal network.",
            priority: "medium",
          },
          {
            title: "Review TLS Certificates",
            description:
              "Audit and update TLS certificates across all internal servers to prevent man-in-the-middle attacks and validation failures.",
            priority: "medium",
          },
          {
            title: "Deploy EDR Solutions",
            description:
              "Implement Endpoint Detection and Response (EDR) solutions to detect and prevent malicious PowerShell execution and other endpoint threats.",
            priority: "high",
          },
        ],
        iocs: [
          {
            type: "ip",
            value: "203.0.113.42",
            context: "Command and Control Server",
            confidence: 95,
          },
          {
            type: "domain",
            value: "suspicious-domain.com",
            context: "DNS Tunneling",
            confidence: 88,
          },
          {
            type: "hash",
            value: "e5b9d6b7a8b3c9d2e1a5f4c3b2a1d0e9",
            context: "Malicious File Hash",
            confidence: 92,
          },
        ],
      }

      // Ensure progress is complete
      setProgress(100)
      setAnalyzing(false)

      // Set the analysis data
      setAnalysis(mockAnalysis)
    } catch (error) {
      console.error("Error analyzing PCAP file:", error)
      setError("Failed to analyze PCAP file. Please try again later.")
      setAnalyzing(false)
    } finally {
      clearInterval(progressInterval)
      setLoading(false)
    }
  }

  useEffect(() => {
    if (analysisId) {
      runAnalysis()
    }
  }, [analysisId])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low":
        return "bg-blue-100 text-blue-800"
      case "medium":
        return "bg-yellow-100 text-yellow-800"
      case "high":
        return "bg-orange-100 text-orange-800"
      case "critical":
        return "bg-red-100 text-red-800"
      default:
        return "bg-gray-100 text-gray-800"
    }
  }

  const getSeverityBgColor = (severity: string) => {
    switch (severity) {
      case "low":
        return "bg-blue-50"
      case "medium":
        return "bg-yellow-50"
      case "high":
        return "bg-orange-50"
      case "critical":
        return "bg-red-50"
      default:
        return "bg-gray-50"
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "malware":
        return <Shield className="h-5 w-5" />
      case "anomaly":
        return <Activity className="h-5 w-5" />
      case "exfiltration":
        return <Network className="h-5 w-5" />
      case "vulnerability":
        return <FileWarning className="h-5 w-5" />
      case "reconnaissance":
        return <Search className="h-5 w-5" />
      default:
        return <AlertTriangle className="h-5 w-5" />
    }
  }

  const getTimelineSeverityColor = (severity: string) => {
    switch (severity) {
      case "info":
        return "bg-blue-100 border-blue-200"
      case "warning":
        return "bg-yellow-100 border-yellow-200"
      case "error":
        return "bg-red-100 border-red-200"
      default:
        return "bg-gray-100 border-gray-200"
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "low":
        return "bg-blue-100 text-blue-800"
      case "medium":
        return "bg-yellow-100 text-yellow-800"
      case "high":
        return "bg-red-100 text-red-800"
      default:
        return "bg-gray-100 text-gray-800"
    }
  }

  const handleInsightClick = (insight: Insight) => {
    setSelectedInsight(selectedInsight?.id === insight.id ? null : insight)
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-red-500">Analysis Error</CardTitle>
        </CardHeader>
        <CardContent>
          <p>{error}</p>
          <Button onClick={runAnalysis} className="mt-4">
            Try Again
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {analyzing && (
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
      )}

      {!analyzing && analysis && (
        <>
          <Card className={getSeverityBgColor(analysis.threatLevel)}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle>Threat Analysis Summary</CardTitle>
                <Badge className={getSeverityColor(analysis.threatLevel)}>
                  {analysis.threatLevel.charAt(0).toUpperCase() + analysis.threatLevel.slice(1)} Threat Level
                </Badge>
              </div>
              <CardDescription>
                Analysis of {analysis.statistics.analyzedPackets.toLocaleString()} packets
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm md:text-base">{analysis.summary}</p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                <div className="bg-white/50 p-3 rounded-lg border">
                  <div className="flex items-center text-sm font-medium">
                    <Shield className="h-4 w-4 mr-2 text-red-500" />
                    Security Findings
                  </div>
                  <div className="text-2xl font-bold mt-1">{analysis.findings.length}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {analysis.findings.filter((f) => f.severity === "critical").length} critical,{" "}
                    {analysis.findings.filter((f) => f.severity === "high").length} high
                  </div>
                </div>

                <div className="bg-white/50 p-3 rounded-lg border">
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

                <div className="bg-white/50 p-3 rounded-lg border">
                  <div className="flex items-center text-sm font-medium">
                    <Network className="h-4 w-4 mr-2 text-blue-500" />
                    Top Talker
                  </div>
                  <div className="text-xl font-bold mt-1">{analysis.statistics.topTalkers[0]?.ip || "Unknown"}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {analysis.statistics.topTalkers[0]?.packets.toLocaleString()} packets (
                    {(analysis.statistics.topTalkers[0]?.bytes / 1024 / 1024).toFixed(2)} MB)
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <Card>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle>Security Findings</CardTitle>
                    <Button variant="outline" size="sm" onClick={runAnalysis} disabled={analyzing}>
                      <RefreshCw className={`h-4 w-4 mr-2 ${analyzing ? "animate-spin" : ""}`} />
                      Refresh Analysis
                    </Button>
                  </div>
                  <CardDescription>AI-detected security issues in your network traffic</CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="flex justify-center items-center h-60">
                      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                    </div>
                  ) : analysis.findings.length > 0 ? (
                    <div className="space-y-4">
                      {analysis.findings.map((finding) => (
                        <Alert
                          key={finding.id}
                          variant="default"
                          className={`${getSeverityBgColor(finding.severity)} cursor-pointer transition-colors ${
                            selectedInsight?.id === finding.id ? "ring-2 ring-primary" : ""
                          }`}
                          onClick={() => handleInsightClick(finding)}
                        >
                          <div className="flex items-start">
                            {getCategoryIcon(finding.category)}
                            <div className="ml-3 flex-1">
                              <div className="flex items-center justify-between">
                                <AlertTitle className="text-base">{finding.title}</AlertTitle>
                                <Badge className={getSeverityColor(finding.severity)}>
                                  {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
                                </Badge>
                              </div>
                              <AlertDescription className="mt-1">{finding.description}</AlertDescription>
                              <div className="mt-2 flex items-center text-xs text-muted-foreground">
                                <span>AI Confidence: {finding.confidence}%</span>
                                <Progress value={finding.confidence} className="h-1 ml-2 w-24" />
                              </div>
                            </div>
                          </div>
                        </Alert>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-10">
                      <p className="text-muted-foreground">No security insights found</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="mt-6">
                <CardHeader className="pb-2">
                  <CardTitle>Recommended Actions</CardTitle>
                  <CardDescription>Steps to address identified security issues</CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="flex justify-center items-center h-40">
                      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                  ) : analysis.recommendations.length > 0 ? (
                    <div className="space-y-4">
                      {analysis.recommendations.map((recommendation, index) => (
                        <div key={index} className="p-4 border rounded-lg bg-white flex items-start">
                          <div
                            className={`p-2 rounded-full ${
                              recommendation.priority === "high"
                                ? "bg-red-100"
                                : recommendation.priority === "medium"
                                  ? "bg-yellow-100"
                                  : "bg-blue-100"
                            } mr-3`}
                          >
                            {recommendation.priority === "high" ? (
                              <Zap className="h-5 w-5 text-red-600" />
                            ) : recommendation.priority === "medium" ? (
                              <AlertTriangle className="h-5 w-5 text-yellow-600" />
                            ) : (
                              <Shield className="h-5 w-5 text-blue-600" />
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
                  ) : (
                    <div className="text-center py-10">
                      <p className="text-muted-foreground">No recommendations available</p>
                    </div>
                  )}
                </CardContent>
              </Card>
              <Card className="mt-6">
                <CardHeader className="pb-2">
                  <CardTitle>Indicators of Compromise</CardTitle>
                  <CardDescription>Potential IOCs extracted from network traffic</CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="flex justify-center items-center h-40">
                      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                  ) : analysis.iocs && analysis.iocs.length > 0 ? (
                    <IOCList iocs={analysis.iocs} />
                  ) : (
                    <div className="text-center py-10">
                      <p className="text-muted-foreground">No indicators of compromise detected</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            <div>
              {selectedInsight ? (
                <Card>
                  <CardHeader className={getSeverityBgColor(selectedInsight.severity)}>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center">
                        {getCategoryIcon(selectedInsight.category)}
                        <span className="ml-2">{selectedInsight.title}</span>
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
                  <CardContent>
                    <Tabs defaultValue="details">
                      <TabsList className="w-full">
                        <TabsTrigger value="details">Details</TabsTrigger>
                        <TabsTrigger value="timeline">Timeline</TabsTrigger>
                        <TabsTrigger value="mitigation">Mitigation</TabsTrigger>
                      </TabsList>
                      <TabsContent value="details" className="pt-4">
                        <div className="space-y-4">
                          <div>
                            <h4 className="text-sm font-medium mb-1">Description</h4>
                            <p className="text-sm">{selectedInsight.description}</p>
                          </div>

                          {selectedInsight.detailedAnalysis && (
                            <div>
                              <h4 className="text-sm font-medium mb-1">Detailed Analysis</h4>
                              <p className="text-sm">{selectedInsight.detailedAnalysis}</p>
                            </div>
                          )}

                          {selectedInsight.affectedHosts && selectedInsight.affectedHosts.length > 0 && (
                            <div>
                              <h4 className="text-sm font-medium mb-1">Affected Hosts</h4>
                              <div className="flex flex-wrap gap-2">
                                {selectedInsight.affectedHosts.map((host, index) => (
                                  <Badge key={index} variant="outline">
                                    {host}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}

                          {selectedInsight.relatedPackets && selectedInsight.relatedPackets.length > 0 && (
                            <div>
                              <h4 className="text-sm font-medium mb-1">Related Packets</h4>
                              <div className="flex flex-wrap gap-2">
                                {selectedInsight.relatedPackets.map((packetId, index) => (
                                  <Badge key={index} variant="secondary">
                                    #{packetId}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </TabsContent>
                      <TabsContent value="timeline" className="pt-4">
                        {selectedInsight.timeline && selectedInsight.timeline.length > 0 ? (
                          <div className="relative pl-6 border-l-2 border-muted space-y-4">
                            {selectedInsight.timeline.map((event, index) => (
                              <div key={index} className="relative">
                                <div className="absolute -left-[25px] w-4 h-4 rounded-full bg-primary"></div>
                                <div className="text-xs text-muted-foreground">{event.time}</div>
                                <div className="text-sm mt-1">{event.event}</div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-sm text-muted-foreground">No timeline available</p>
                        )}
                      </TabsContent>
                      <TabsContent value="mitigation" className="pt-4">
                        {selectedInsight.mitigationSteps && selectedInsight.mitigationSteps.length > 0 ? (
                          <div className="space-y-4">
                            <div>
                              <h4 className="text-sm font-medium mb-2">Recommended Actions</h4>
                              <ul className="space-y-2">
                                {selectedInsight.mitigationSteps.map((step, index) => (
                                  <li key={index} className="flex items-start">
                                    <span className="bg-primary text-primary-foreground rounded-full w-5 h-5 flex items-center justify-center text-xs mr-2 mt-0.5">
                                      {index + 1}
                                    </span>
                                    <span className="text-sm">{step}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>

                            {selectedInsight.references && selectedInsight.references.length > 0 && (
                              <div>
                                <h4 className="text-sm font-medium mb-2">References</h4>
                                <ul className="space-y-1">
                                  {selectedInsight.references.map((ref, index) => (
                                    <li key={index}>
                                      <a
                                        href={ref.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-sm text-blue-600 hover:underline"
                                      >
                                        {ref.title}
                                      </a>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div>
                            <h4 className="text-sm font-medium mb-2">Recommendation</h4>
                            <p className="text-sm">{selectedInsight.recommendation}</p>
                          </div>
                        )}
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardHeader>
                    <CardTitle>Finding Details</CardTitle>
                    <CardDescription>Select a finding to view details</CardDescription>
                  </CardHeader>
                  <CardContent className="text-center py-8 text-muted-foreground">
                    <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-muted" />
                    <p>Click on a security finding to view detailed information</p>
                  </CardContent>
                </Card>
              )}

              <Card className="mt-6">
                <CardHeader className="pb-2">
                  <CardTitle>Network Activity Timeline</CardTitle>
                  <CardDescription>Chronological view of significant events</CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="flex justify-center items-center h-40">
                      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                  ) : analysis.timeline.length > 0 ? (
                    <div className="relative pl-6 border-l-2 border-muted space-y-4 max-h-[300px] overflow-y-auto pr-2">
                      {analysis.timeline.map((event, index) => (
                        <div key={index} className="relative">
                          <div
                            className={`absolute -left-[25px] w-4 h-4 rounded-full ${
                              event.severity === "error"
                                ? "bg-red-500"
                                : event.severity === "warning"
                                  ? "bg-yellow-500"
                                  : "bg-blue-500"
                            }`}
                          ></div>
                          <div className="text-xs text-muted-foreground">{event.time}</div>
                          <div
                            className={`text-sm mt-1 p-2 rounded-md ${getTimelineSeverityColor(event.severity)} border`}
                          >
                            {event.event}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-10">
                      <p className="text-muted-foreground">No timeline events available</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="mt-6">
                <CardHeader className="pb-2">
                  <CardTitle>Traffic Statistics</CardTitle>
                  <CardDescription>Protocol distribution and traffic patterns</CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="flex justify-center items-center h-40">
                      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div>
                        <h4 className="text-sm font-medium mb-2">Protocol Distribution</h4>
                        <div className="space-y-2">
                          {Object.entries(analysis.statistics.protocols).map(([protocol, count]) => {
                            const percentage = Math.round((count / analysis.statistics.totalPackets) * 100)
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
                            )
                          })}
                        </div>
                      </div>

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
                                  <div className="text-sm font-medium">{talker.ip}</div>
                                  <div className="text-xs text-muted-foreground">
                                    {talker.packets.toLocaleString()} packets
                                  </div>
                                </div>
                              </div>
                              <div className="text-sm">{(talker.bytes / 1024 / 1024).toFixed(2)} MB</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
