// components/ioc-validator.tsx
"use client";

import React, { useState } from "react"; // Import React
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Loader2, AlertTriangle, Shield, CheckCircle, XCircle, Clock, ExternalLink, Info, ListChecks, Users, BarChart3 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area"; // Impor ScrollBar juga

// Impor interface dari berkas lib jika sudah dibuat
// (Anda mungkin perlu membuat berkas ini atau mendefinisikannya secara lokal jika belum)
// Untuk sekarang, kita akan definisikan secara lokal agar mandiri
interface OTXIndicatorDetails {
  indicator: string; type: string; description?: string; title?: string;
  references?: string[]; malware_families?: string[]; tags?: string[];
  pulse_info?: { count: number; pulses: Array<{ id: string; name: string; tags: string[]; created: string; adversary?: string; }>; };
}
interface AbuseIPDBReport {
  ipAddress: string; isPublic: boolean; ipVersion: number; isWhitelisted: boolean | null;
  abuseConfidenceScore: number; countryCode: string | null; countryName: string | null;
  usageType: string | null; isp: string; domain: string | null; hostnames: string[];
  totalReports: number; numDistinctUsers: number; lastReportedAt: string | null;
}
interface TalosReputation { ip: string; verdict: string | null; errorMessage?: string; }

// Impor tipe respons VirusTotal dan MalwareBazaar (jika sudah didefinisikan di lib)
// Jika tidak, Anda bisa menggunakan 'any' atau mendefinisikan struktur dasar di sini
// import type { VirusTotalResponse as VTResponseType } from "@/lib/virustotal";
import type { MalwareBazaarResponse as MBResponseType } from "@/lib/malwarebazaar";
import * as VirusTotal from "@/lib/virustotal";
import type { OTXIndicatorDetails } from "@/lib/otx";
import type { AbuseIPDBReport } from "@/lib/abuseipdb";
import type { TalosReputation } from "@/lib/talosintelligence";


interface IOCValidatorProps {
  defaultIoc?: { type: string; value: string; };
  onValidationComplete?: (results: any) => void;
}

interface ValidationResult {
  ioc: { type: string; value: string; };
  results: {
    virusTotal?: VTResponseType["data"]["attributes"];
    malwareBazaar?: { detected: boolean; details: MBResponseType["data"][0] | null; };
    otxAlienvault?: OTXIndicatorDetails | { message: string };
    abuseIPDB?: AbuseIPDBReport | { message: string };
    talosIntelligence?: TalosReputation | { message: string };
  };
  errors?: {
    virusTotal?: string; malwareBazaar?: string; otxAlienvault?: string;
    abuseIPDB?: string; talosIntelligence?: string;
  };
}

export function IOCValidator({ defaultIoc, onValidationComplete }: IOCValidatorProps) {
  const [iocType, setIocType] = useState<string>(defaultIoc?.type || "ip");
  const [iocValue, setIocValue] = useState<string>(defaultIoc?.value || "");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ValidationResult | null>(null);

  const validateIOC = async () => { /* ... sama seperti sebelumnya ... */
    if (!iocValue.trim()) {
      setError("Please enter a value to validate");
      return;
    }
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const response = await fetch("/api/validate-ioc", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: iocType, value: iocValue.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
      setResults(data);
      if (onValidationComplete) onValidationComplete(data);
    } catch (err) {
      console.error("Validation error:", err);
      setError(err instanceof Error ? err.message : "An error occurred during validation");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => { if (e.key === "Enter" && !loading) validateIOC(); };

  const getThreatLevelBadge = (threatLevel?: "clean" | "suspicious" | "malicious" | "favorable" | "neutral" | "unfavorable/poor" | string) => {
    const level = threatLevel?.toLowerCase() || "unknown";
    switch (level) {
      case "malicious":
      case "unfavorable/poor":
        return <Badge className="bg-red-100 text-red-800 dark:bg-red-900/70 dark:text-red-300"><XCircle className="h-3 w-3 mr-1" /> {threatLevel}</Badge>;
      case "suspicious":
        return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-800/70 dark:text-yellow-200"><AlertTriangle className="h-3 w-3 mr-1" /> {threatLevel}</Badge>;
      case "clean":
      case "favorable":
        return <Badge className="bg-green-100 text-green-800 dark:bg-green-900/70 dark:text-green-300"><CheckCircle className="h-3 w-3 mr-1" /> {threatLevel}</Badge>;
      case "neutral":
         return <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-700 dark:text-blue-200"><Info className="h-3 w-3 mr-1" /> {threatLevel}</Badge>;
      default:
        return <Badge className="bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"><Clock className="h-3 w-3 mr-1" /> {threatLevel || "Unknown"}</Badge>;
    }
  };
  
  const getPlaceholder = (type: string) => { /* ... sama ... */ 
    switch (type) {
      case "ip": return "e.g., 8.8.8.8";
      case "domain": return "e.g., example.com";
      case "url": return "e.g., https://example.com/path";
      case "hash": return "e.g., 44d88612fea8a8f36de82e1278abb02f";
      default: return "Enter value to validate";
    }
  };

  const getExternalLink = (service: "virustotal" | "otx" | "abuseipdb" | "talos", type: string, value: string) => { /* ... sama seperti sebelumnya ... */
    const encodedValue = encodeURIComponent(value);
    switch (service) {
      case "virustotal":
        switch (type) {
          case "ip": return `https://www.virustotal.com/gui/ip-address/${encodedValue}`;
          case "domain": return `https://www.virustotal.com/gui/domain/${encodedValue}`;
          case "url": return `https://www.virustotal.com/gui/url/${Buffer.from(value).toString("base64").replace(/=+$/, "")}`;
          case "hash": return `https://www.virustotal.com/gui/file/${encodedValue}`;
        }
        break;
      case "otx":
        let otxTypePath = "";
        switch (type) {
          case "ip": otxTypePath = `IPv4/${encodedValue}`; break;
          case "domain": otxTypePath = `domain/${encodedValue}`; break;
          case "url": otxTypePath = `url/${encodedValue}`; break;
          case "hash": otxTypePath = `file/${encodedValue}`; break;
        }
        return `https://otx.alienvault.com/indicator/${otxTypePath}`;
      case "abuseipdb":
        return `https://www.abuseipdb.com/check/${encodedValue}`;
      case "talos":
        return `https://talosintelligence.com/reputation_center/lookup?search=${encodedValue}`;
    }
    return "#";
  };

  const formatFileSize = (bytes?: number): string => { /* ... sama, tambahkan pengecekan undefined ... */ 
    if (bytes === undefined || bytes === null) return "N/A";
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatDate = (dateInput?: string | number): string => { /* ... sama seperti sebelumnya ... */ 
    if (!dateInput) return "N/A";
    try {
      const date = typeof dateInput === 'string' && !isNaN(Number(dateInput)) && dateInput.length === 10 ? new Date(Number(dateInput) * 1000) : new Date(dateInput);
      if (isNaN(date.getTime())) return String(dateInput); 
      return date.toLocaleString();
    } catch {
      return String(dateInput); 
    }
  };


  return (
    <Card>
      <CardHeader>
        <CardTitle>IOC Validator</CardTitle>
        <CardDescription>Validate IOCs using VirusTotal, MalwareBazaar, OTX, AbuseIPDB, and Talos Intelligence</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-1">
              <Label htmlFor="ioc-type">IOC Type</Label>
              <Select value={iocType} onValueChange={setIocType} disabled={loading}>
                <SelectTrigger id="ioc-type"><SelectValue placeholder="Select type" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip">IP Address</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="url">URL</SelectItem>
                  <SelectItem value="hash">File Hash</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="md:col-span-2">
              <Label htmlFor="ioc-value">Value</Label>
              <Input id="ioc-value" value={iocValue} onChange={(e) => setIocValue(e.target.value)} onKeyPress={handleKeyPress} placeholder={getPlaceholder(iocType)} disabled={loading} />
            </div>
            <div className="md:col-span-1 flex items-end">
              <Button onClick={validateIOC} disabled={loading || !iocValue.trim()} className="w-full">
                {loading ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Validating...</> : "Validate"}
              </Button>
            </div>
          </div>

          {error && (
            <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>Error</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>
          )}

          {results && (
            <div className="mt-4 space-y-4">
              <h3 className="text-lg font-medium">
                Results for {results.ioc.type}: <span className="font-bold font-mono break-all">{results.ioc.value}</span>
              </h3>
              <Tabs defaultValue="virustotal">
                <ScrollArea className="w-full whitespace-nowrap border-b">
                  <TabsList className="inline-flex h-auto">
                    <TabsTrigger value="virustotal">VirusTotal</TabsTrigger>
                    {results.results.malwareBazaar && <TabsTrigger value="malwarebazaar">MalwareBazaar</TabsTrigger>}
                    {results.results.otxAlienvault && <TabsTrigger value="otx">OTX</TabsTrigger>}
                    {results.results.abuseIPDB && <TabsTrigger value="abuseipdb">AbuseIPDB</TabsTrigger>}
                    {results.results.talosIntelligence && <TabsTrigger value="talos">Talos</TabsTrigger>}
                    {results.errors && Object.keys(results.errors).length > 0 && (
                      <TabsTrigger value="errors" className="text-destructive">Errors</TabsTrigger>
                    )}
                  </TabsList>
                  <ScrollBar orientation="horizontal" />
                </ScrollArea>
                
                <TabsContent value="virustotal" className="pt-4">
                  {results.results.virusTotal ? (
                    <div className="space-y-4">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="font-medium">VirusTotal Assessment</div>
                                {results.results.virusTotal.last_analysis_stats &&
                                    <div className="text-sm text-muted-foreground">
                                    Detection Ratio: {VirusTotal.getDetectionRatio(results.results.virusTotal.last_analysis_stats)}
                                    </div>
                                }
                                {results.results.virusTotal.last_analysis_date && (
                                <div className="text-xs text-muted-foreground">
                                    Last analyzed: {formatDate(results.results.virusTotal.last_analysis_date)}
                                </div>
                                )}
                            </div>
                            {results.results.virusTotal.last_analysis_stats && getThreatLevelBadge(VirusTotal.getThreatLevel(results.results.virusTotal.last_analysis_stats))}
                        </div>
                        <Button variant="outline" size="sm" asChild className="mt-2">
                            <a href={getExternalLink("virustotal", results.ioc.type, results.ioc.value)} target="_blank" rel="noopener noreferrer">
                                <ExternalLink className="h-4 w-4 mr-1" /> View on VirusTotal
                            </a>
                        </Button>
                         {results.results.virusTotal.reputation !== undefined && (
                            <div className="p-3 bg-muted/50 dark:bg-slate-800 rounded-md">
                            <div className="text-sm font-medium">Community Reputation</div>
                            <div className="text-lg font-bold">{results.results.virusTotal.reputation}</div>
                            </div>
                        )}
                        {results.results.virusTotal.last_analysis_results && Object.keys(results.results.virusTotal.last_analysis_results).length > 0 && (
                            <div>
                            <h4 className="text-sm font-medium mb-2">Top Detections (VT):</h4>
                             <ScrollArea className="h-48 border rounded-md">
                                <Table className="text-xs">
                                    <TableHeader><TableRow><TableHead>Engine</TableHead><TableHead>Category</TableHead><TableHead>Result</TableHead></TableRow></TableHeader>
                                    <TableBody>
                                    {VirusTotal.getTopDetections(results.results.virusTotal.last_analysis_results).map((engine, index) => (
                                        <TableRow key={index}>
                                        <TableCell>{engine.engine}</TableCell>
                                        <TableCell><Badge variant={engine.category === "malicious" || engine.category === "suspicious" ? "destructive" : "secondary"}>{engine.category}</Badge></TableCell>
                                        <TableCell>{engine.result}</TableCell>
                                        </TableRow>
                                    ))}
                                    </TableBody>
                                </Table>
                             </ScrollArea>
                            </div>
                        )}
                    </div>
                    ) : (
                    <div className="text-center py-8 text-muted-foreground">
                        <Shield className="h-12 w-12 mx-auto mb-4 text-muted" />
                        <p>No results from VirusTotal.</p>
                        {results.errors?.virusTotal && <p className="text-xs text-destructive mt-1">Error: {results.errors.virusTotal}</p>}
                    </div>
                    )}
                </TabsContent>

                {results.results.malwareBazaar && (
                  <TabsContent value="malwarebazaar" className="pt-4">
                     {results.results.malwareBazaar.detected && results.results.malwareBazaar.details ? (
                      <div className="space-y-4 text-sm">
                        <Alert variant="destructive">
                          <Shield className="h-4 w-4" />
                          <AlertTitle>Malware Detected by MalwareBazaar!</AlertTitle>
                        </Alert>
                        <p><strong>File Name:</strong> <span className="font-mono">{results.results.malwareBazaar.details.file_name}</span></p>
                        <p><strong>File Type:</strong> {results.results.malwareBazaar.details.file_type}</p>
                        <p><strong>Size:</strong> {formatFileSize(results.results.malwareBazaar.details.file_size)}</p>
                        <p><strong>First Seen:</strong> {formatDate(results.results.malwareBazaar.details.first_seen)}</p>
                        <p><strong>Last Seen:</strong> {formatDate(results.results.malwareBazaar.details.last_seen)}</p>
                        <p><strong>Signature:</strong> {results.results.malwareBazaar.details.signature || "N/A"}</p>
                        <p><strong>Reporter:</strong> {results.results.malwareBazaar.details.reporter}</p>
                        {results.results.malwareBazaar.details.tags && results.results.malwareBazaar.details.tags.length > 0 &&
                           <div><strong>Tags:</strong> <div className="flex flex-wrap gap-1 mt-1">{results.results.malwareBazaar.details.tags.map(tag => <Badge key={tag} variant="destructive">{tag}</Badge>)}</div></div>
                        }
                      </div>
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-500" />
                        <p>Not found or not detected by MalwareBazaar.</p>
                         {results.errors?.malwareBazaar && <p className="text-xs text-destructive mt-1">Error: {results.errors.malwareBazaar}</p>}
                      </div>
                    )}
                  </TabsContent>
                )}

                {results.results.otxAlienvault && (
                  <TabsContent value="otx" className="pt-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center"><ListChecks className="h-5 w-5 mr-2 text-blue-500" /> OTX AlienVault Results</CardTitle>
                         <Button variant="outline" size="sm" asChild className="mt-2 w-fit">
                            <a href={getExternalLink("otx", results.ioc.type, results.ioc.value)} target="_blank" rel="noopener noreferrer">
                                <ExternalLink className="h-4 w-4 mr-1" /> View on OTX
                            </a>
                        </Button>
                      </CardHeader>
                      <CardContent className="space-y-3 text-sm">
                        {(typeof results.results.otxAlienvault === 'object' && 'message' in results.results.otxAlienvault) ? (
                          <p className="text-muted-foreground">{(results.results.otxAlienvault as { message: string }).message}</p>
                        ) : (
                          <>
                            {(results.results.otxAlienvault as OTXIndicatorDetails).title && <p><strong>Title:</strong> {(results.results.otxAlienvault as OTXIndicatorDetails).title}</p>}
                            {(results.results.otxAlienvault as OTXIndicatorDetails).description && <p><strong>Description:</strong> {(results.results.otxAlienvault as OTXIndicatorDetails).description}</p>}
                            
                            {(results.results.otxAlienvault as OTXIndicatorDetails).tags && (results.results.otxAlienvault as OTXIndicatorDetails).tags!.length > 0 && (
                              <div>
                                <strong>Tags:</strong>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {(results.results.otxAlienvault as OTXIndicatorDetails).tags!.map(tag => <Badge key={tag} variant="secondary">{tag}</Badge>)}
                                </div>
                              </div>
                            )}

                            {(results.results.otxAlienvault as OTXIndicatorDetails).pulse_info && (results.results.otxAlienvault as OTXIndicatorDetails).pulse_info!.count > 0 ? (
                              <div>
                                <p><strong>Related Pulses:</strong> {(results.results.otxAlienvault as OTXIndicatorDetails).pulse_info!.count}</p>
                                <ScrollArea className="h-40 border rounded-md mt-1 p-2">
                                  <ul className="list-disc pl-5 space-y-1 text-xs">
                                    {(results.results.otxAlienvault as OTXIndicatorDetails).pulse_info!.pulses.slice(0, 10).map(pulse => (
                                      <li key={pulse.id}>
                                        <a href={`https://otx.alienvault.com/pulse/${pulse.id}`} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline dark:text-blue-400">
                                          {pulse.name}
                                        </a> 
                                        (Tags: {pulse.tags.join(', ') || 'N/A'})
                                      </li>
                                    ))}
                                  </ul>
                                </ScrollArea>
                              </div>
                            ) : (
                              <p className="text-muted-foreground">No related OTX pulses found.</p>
                            )}
                          </>
                        )}
                        {results.errors?.otxAlienvault && <p className="text-xs text-destructive mt-1">Error: {results.errors.otxAlienvault}</p>}
                      </CardContent>
                    </Card>
                  </TabsContent>
                )}

                {results.results.abuseIPDB && (
                  <TabsContent value="abuseipdb" className="pt-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center">
                          <Users className="h-5 w-5 mr-2 text-red-500" /> AbuseIPDB Results
                        </CardTitle>
                        <Button variant="outline" size="sm" asChild className="mt-2 w-fit">
                          <a href={getExternalLink("abuseipdb", results.ioc.type, results.ioc.value)} target="_blank" rel="noopener noreferrer">
                            <ExternalLink className="h-4 w-4 mr-1" /> View on AbuseIPDB
                          </a>
                        </Button>
                      </CardHeader>
                      <CardContent className="space-y-2 text-sm">
                        {(typeof results.results.abuseIPDB === 'object' && 'message' in results.results.abuseIPDB) ? (
                          <p className="text-muted-foreground">{(results.results.abuseIPDB as { message: string }).message}</p>
                        ) : (
                          <>
                            <p><strong>Abuse Confidence Score:</strong> <Badge variant={(results.results.abuseIPDB as AbuseIPDBReport).abuseConfidenceScore > 75 ? "destructive" : (results.results.abuseIPDB as AbuseIPDBReport).abuseConfidenceScore > 25 ? "default" : "secondary" }>{(results.results.abuseIPDB as AbuseIPDBReport).abuseConfidenceScore}%</Badge></p>
                            {(results.results.abuseIPDB as AbuseIPDBReport).countryCode && <p><strong>Country:</strong> {(results.results.abuseIPDB as AbuseIPDBReport).countryCode} ({(results.results.abuseIPDB as AbuseIPDBReport).countryName})</p>}
                            {(results.results.abuseIPDB as AbuseIPDBReport).usageType && <p><strong>Usage Type:</strong> {(results.results.abuseIPDB as AbuseIPDBReport).usageType}</p>}
                            {(results.results.abuseIPDB as AbuseIPDBReport).isp && <p><strong>ISP:</strong> {(results.results.abuseIPDB as AbuseIPDBReport).isp}</p>}
                            {(results.results.abuseIPDB as AbuseIPDBReport).domain && <p><strong>Domain:</strong> {(results.results.abuseIPDB as AbuseIPDBReport).domain}</p>}
                            <p><strong>Total Reports:</strong> {(results.results.abuseIPDB as AbuseIPDBReport).totalReports}</p>
                            <p><strong>Distinct Users Reporting:</strong> {(results.results.abuseIPDB as AbuseIPDBReport).numDistinctUsers}</p>
                            {(results.results.abuseIPDB as AbuseIPDBReport).lastReportedAt && <p><strong>Last Reported:</strong> {formatDate((results.results.abuseIPDB as AbuseIPDBReport).lastReportedAt!)}</p>}
                          </>
                        )}
                        {results.errors?.abuseIPDB && <p className="text-xs text-destructive mt-1">Error: {results.errors.abuseIPDB}</p>}
                      </CardContent>
                    </Card>
                  </TabsContent>
                )}

                {results.results.talosIntelligence && (
                  <TabsContent value="talos" className="pt-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center">
                          <BarChart3 className="h-5 w-5 mr-2 text-teal-500" /> Talos Intelligence Reputation
                        </CardTitle>
                        <Button variant="outline" size="sm" asChild className="mt-2 w-fit">
                           <a href={getExternalLink("talos", results.ioc.type, results.ioc.value)} target="_blank" rel="noopener noreferrer">
                             <ExternalLink className="h-4 w-4 mr-1" /> View on Talos
                           </a>
                        </Button>
                      </CardHeader>
                      <CardContent className="space-y-2 text-sm">
                        {(typeof results.results.talosIntelligence === 'object' && 'message' in results.results.talosIntelligence) ? (
                          <p className="text-muted-foreground">{(results.results.talosIntelligence as { message: string }).message}</p>
                        ) : (
                          <>
                            <p><strong>IP:</strong> {(results.results.talosIntelligence as TalosReputation).ip}</p>
                            <p><strong>Verdict:</strong> {getThreatLevelBadge((results.results.talosIntelligence as TalosReputation).verdict || "Unknown")}</p>
                          </>
                        )}
                        {results.errors?.talosIntelligence && <p className="text-xs text-destructive mt-1">Error: {results.errors.talosIntelligence}</p>}
                      </CardContent>
                    </Card>
                  </TabsContent>
                )}

                {results.errors && Object.keys(results.errors).length > 0 && (
                  <TabsContent value="errors" className="pt-4">
                    <div className="space-y-4">
                      {results.errors.virusTotal && (<Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>VirusTotal Error</AlertTitle><AlertDescription>{results.errors.virusTotal}</AlertDescription></Alert>)}
                      {results.errors.malwareBazaar && (<Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>MalwareBazaar Error</AlertTitle><AlertDescription>{results.errors.malwareBazaar}</AlertDescription></Alert>)}
                      {results.errors.otxAlienvault && (<Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>OTX Error</AlertTitle><AlertDescription>{results.errors.otxAlienvault}</AlertDescription></Alert>)}
                      {results.errors.abuseIPDB && (<Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>AbuseIPDB Error</AlertTitle><AlertDescription>{results.errors.abuseIPDB}</AlertDescription></Alert>)}
                      {results.errors.talosIntelligence && (<Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>Talos Intelligence Error</AlertTitle><AlertDescription>{results.errors.talosIntelligence}</AlertDescription></Alert>)}
                    </div>
                  </TabsContent>
                )}
              </Tabs>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
