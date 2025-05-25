// components/ioc-validator.tsx
"use client";

import type React from "react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Loader2, AlertTriangle, Shield, CheckCircle, XCircle, Clock, ExternalLink, Info, ListChecks } from "lucide-react"; // Tambahkan ikon jika perlu
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area"; // Impor ScrollArea

// --- TAMBAHKAN INTERFACE INI (atau impor dari lib/otx.ts jika Anda memindahkannya) ---
interface OTXIndicatorDetails {
  indicator: string;
  type: string;
  description?: string;
  title?: string;
  references?: string[];
  malware_families?: string[];
  tags?: string[];
  pulse_info?: {
    count: number;
    pulses: Array<{
      id: string;
      name: string;
      tags: string[];
      created: string;
      adversary?: string;
    }>;
  };
}
// --- SELESAI PENAMBAHAN INTERFACE ---


interface IOCValidatorProps {
  defaultIoc?: {
    type: string;
    value: string;
  };
  onValidationComplete?: (results: any) => void;
}

interface ValidationResult {
  ioc: {
    type: string;
    value: string;
  };
  results: {
    virusTotal?: {
      detectionRatio: string;
      threatLevel: "clean" | "suspicious" | "malicious";
      engines: Array<{
        name: string;
        category: string;
        result: string;
      }>;
      lastAnalysisDate?: string;
      reputation?: number;
    };
    malwareBazaar?: {
      detected: boolean;
      details: {
        fileName: string;
        fileType: string;
        fileSize: number;
        firstSeen: string;
        lastSeen: string;
        tags: string[];
        signature: string | null;
        reporter: string;
        deliveryMethod: string;
      } | null;
    };
    // --- TAMBAHKAN BAGIAN INI ---
    otxAlienvault?: OTXIndicatorDetails | { message: string };
    // --- SELESAI PENAMBAHAN ---
  };
  errors?: {
    virusTotal?: string;
    malwareBazaar?: string;
    // --- TAMBAHKAN BAGIAN INI ---
    otxAlienvault?: string;
    // --- SELESAI PENAMBAHAN ---
  };
}

export function IOCValidator({ defaultIoc, onValidationComplete }: IOCValidatorProps) {
  const [iocType, setIocType] = useState<string>(defaultIoc?.type || "ip");
  const [iocValue, setIocValue] = useState<string>(defaultIoc?.value || "");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ValidationResult | null>(null);

  const validateIOC = async () => {
    // ... (fungsi validateIOC tetap sama) ...
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
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          type: iocType,
          value: iocValue.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      setResults(data);
      if (onValidationComplete) {
        onValidationComplete(data);
      }
    } catch (err) {
      console.error("Validation error:", err);
      setError(err instanceof Error ? err.message : "An error occurred during validation");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !loading) {
      validateIOC();
    }
  };

  const getThreatLevelBadge = (threatLevel: string) => {
    // ... (fungsi ini tetap sama) ...
    switch (threatLevel) {
      case "malicious":
        return (
          <Badge className="bg-red-100 text-red-800 dark:bg-red-900/70 dark:text-red-300">
            <XCircle className="h-3 w-3 mr-1" />
            Malicious
          </Badge>
        );
      case "suspicious":
        return (
          <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-800/70 dark:text-yellow-200">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Suspicious
          </Badge>
        );
      case "clean":
        return (
          <Badge className="bg-green-100 text-green-800 dark:bg-green-900/70 dark:text-green-300">
            <CheckCircle className="h-3 w-3 mr-1" />
            Clean
          </Badge>
        );
      default:
        return (
          <Badge className="bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
            <Clock className="h-3 w-3 mr-1" />
            Unknown
          </Badge>
        );
    }
  };

  const getPlaceholder = (type: string) => {
    // ... (fungsi ini tetap sama) ...
    switch (type) {
      case "ip":
        return "e.g., 8.8.8.8";
      case "domain":
        return "e.g., example.com";
      case "url":
        return "e.g., https://example.com/path";
      case "hash":
        return "e.g., 44d88612fea8a8f36de82e1278abb02f";
      default:
        return "Enter value to validate";
    }
  };

  // --- MODIFIKASI FUNGSI INI UNTUK OTX ---
  const getExternalLink = (service: "virustotal" | "otx", type: string, value: string) => {
    const encodedValue = encodeURIComponent(value);
    if (service === "virustotal") {
      switch (type) {
        case "ip": return `https://www.virustotal.com/gui/ip-address/${encodedValue}`;
        case "domain": return `https://www.virustotal.com/gui/domain/${encodedValue}`;
        case "url": return `https://www.virustotal.com/gui/url/${Buffer.from(value).toString("base64").replace(/=+$/, "")}`; // VT URL ID
        case "hash": return `https://www.virustotal.com/gui/file/${encodedValue}`;
        default: return "#";
      }
    } else if (service === "otx") {
      let otxTypePath = "";
      switch (type) {
        case "ip": otxTypePath = `IPv4/${encodedValue}`; break;
        case "domain": otxTypePath = `domain/${encodedValue}`; break;
        case "url": otxTypePath = `url/${encodedValue}`; break; // OTX URL search might differ
        case "hash": otxTypePath = `file/${encodedValue}`; break;
        default: return "#";
      }
      return `https://otx.alienvault.com/indicator/${otxTypePath}`;
    }
    return "#";
  };
  // --- SELESAI MODIFIKASI ---

  const formatFileSize = (bytes: number): string => {
    // ... (fungsi ini tetap sama) ...
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatDate = (dateInput?: string | number): string => {
    // ... (fungsi ini tetap sama, mungkin perlu penyesuaian jika OTX mengembalikan format tanggal berbeda) ...
    if (!dateInput) return "N/A";
    try {
      // Jika input adalah string ISO atau timestamp number
      const date = typeof dateInput === 'string' && !isNaN(Number(dateInput)) ? new Date(Number(dateInput) * 1000) : new Date(dateInput);
      if (isNaN(date.getTime())) return String(dateInput); // Jika tidak valid, kembalikan input asli
      return date.toLocaleString();
    } catch {
      return String(dateInput); // Fallback
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>IOC Validator</CardTitle>
        <CardDescription>Validate indicators of compromise using VirusTotal, MalwareBazaar, and OTX AlienVault</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* ... (Input form tetap sama) ... */}
           <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-1">
              <Label htmlFor="ioc-type">IOC Type</Label>
              <Select value={iocType} onValueChange={setIocType} disabled={loading}>
                <SelectTrigger id="ioc-type">
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
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
              <Input
                id="ioc-value"
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={getPlaceholder(iocType)}
                disabled={loading}
              />
            </div>
            <div className="md:col-span-1 flex items-end">
              <Button onClick={validateIOC} disabled={loading || !iocValue.trim()} className="w-full">
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Validating...
                  </>
                ) : (
                  "Validate"
                )}
              </Button>
            </div>
          </div>


          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {results && (
            <div className="mt-4 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <h3 className="text-lg font-medium">
                  Results for {results.ioc.type}: <span className="font-bold font-mono break-all">{results.ioc.value}</span>
                </h3>
                {/* Tombol link eksternal bisa digabung atau dibuat terpisah per layanan */}
              </div>

              <Tabs defaultValue="virustotal">
                <TabsList className="grid w-full grid-cols-2 md:grid-cols-3 lg:grid-cols-4"> {/* Sesuaikan grid cols */}
                  <TabsTrigger value="virustotal">VirusTotal</TabsTrigger>
                  {results.results.malwareBazaar && <TabsTrigger value="malwarebazaar">MalwareBazaar</TabsTrigger>}
                  {/* --- TAMBAHKAN TRIGGER UNTUK OTX --- */}
                  {results.results.otxAlienvault && <TabsTrigger value="otx">OTX AlienVault</TabsTrigger>}
                  {/* --- SELESAI PENAMBAHAN --- */}
                  {results.errors && Object.keys(results.errors).length > 0 && (
                    <TabsTrigger value="errors" className="text-destructive">Errors</TabsTrigger>
                  )}
                </TabsList>

                <TabsContent value="virustotal" className="pt-4">
                  {/* ... (Konten VirusTotal tetap sama) ... */}
                  {results.results.virusTotal ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center">
                          <div
                            className={`p-2 rounded-full mr-3 ${
                              results.results.virusTotal.threatLevel === "malicious"
                                ? "bg-red-100 dark:bg-red-900/70"
                                : results.results.virusTotal.threatLevel === "suspicious"
                                  ? "bg-yellow-100 dark:bg-yellow-800/70"
                                  : "bg-green-100 dark:bg-green-900/70"
                            }`}
                          >
                            {results.results.virusTotal.threatLevel === "malicious" ? (
                              <XCircle className="h-5 w-5 text-red-600 dark:text-red-300" />
                            ) : results.results.virusTotal.threatLevel === "suspicious" ? (
                              <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-200" />
                            ) : (
                              <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-300" />
                            )}
                          </div>
                          <div>
                            <div className="font-medium">VirusTotal Assessment</div>
                            <div className="text-sm text-muted-foreground">
                              Detection Ratio: {results.results.virusTotal.detectionRatio}
                            </div>
                            {results.results.virusTotal.lastAnalysisDate && (
                              <div className="text-xs text-muted-foreground">
                                Last analyzed: {formatDate(results.results.virusTotal.lastAnalysisDate)}
                              </div>
                            )}
                          </div>
                        </div>
                        {getThreatLevelBadge(results.results.virusTotal.threatLevel)}
                      </div>
                      <Button variant="outline" size="sm" asChild className="mt-2">
                          <a href={getExternalLink("virustotal", results.ioc.type, results.ioc.value)} target="_blank" rel="noopener noreferrer">
                            <ExternalLink className="h-4 w-4 mr-1" /> View on VirusTotal
                          </a>
                      </Button>
                      {/* ... sisa detail VT ... */}
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
                    {/* ... (Konten MalwareBazaar tetap sama) ... */}
                    {results.results.malwareBazaar.detected && results.results.malwareBazaar.details ? (
                      <div className="space-y-4">
                        <Alert variant="destructive">
                          <Shield className="h-4 w-4" />
                          <AlertTitle>Malware Detected by MalwareBazaar!</AlertTitle>
                        </Alert>
                        {/* ... sisa detail MB ... */}
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

                {/* --- TAMBAHKAN KONTEN TAB UNTUK OTX --- */}
                {results.results.otxAlienvault && (
                  <TabsContent value="otx" className="pt-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center">
                          {/* Anda bisa menambahkan ikon untuk OTX jika mau */}
                          <ListChecks className="h-5 w-5 mr-2 text-blue-500" /> 
                          OTX AlienVault Results
                        </CardTitle>
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
                                    {(results.results.otxAlienvault as OTXIndicatorDetails).pulse_info!.pulses.slice(0, 10).map(pulse => ( // Batasi 10 pulse untuk tampilan
                                      <li key={pulse.id}>
                                        <a href={`https://otx.alienvault.com/pulse/${pulse.id}`} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                                          {pulse.name}
                                        </a> 
                                        (Tags: {pulse.tags.join(', ') || 'N/A'})
                                      </li>
                                    ))}
                                  </ul>
                                </ScrollArea>
                              </div>
                            ) : (
                              <p>No related pulses found in OTX.</p>
                            )}
                          </>
                        )}
                        {results.errors?.otxAlienvault && <p className="text-xs text-destructive mt-1">Error: {results.errors.otxAlienvault}</p>}
                      </CardContent>
                    </Card>
                  </TabsContent>
                )}
                {/* --- SELESAI PENAMBAHAN KONTEN OTX --- */}

                {results.errors && Object.keys(results.errors).length > 0 && (
                  <TabsContent value="errors" className="pt-4">
                    {/* ... (Konten Error tetap sama) ... */}
                     <div className="space-y-4">
                      {results.errors.virusTotal && (
                        <Alert variant="destructive">
                          <AlertTriangle className="h-4 w-4" />
                          <AlertTitle>VirusTotal Error</AlertTitle>
                          <AlertDescription>{results.errors.virusTotal}</AlertDescription>
                        </Alert>
                      )}
                      {results.errors.malwareBazaar && (
                        <Alert variant="destructive">
                          <AlertTriangle className="h-4 w-4" />
                          <AlertTitle>MalwareBazaar Error</AlertTitle>
                          <AlertDescription>{results.errors.malwareBazaar}</AlertDescription>
                        </Alert>
                      )}
                       {results.errors.otxAlienvault && (
                        <Alert variant="destructive">
                          <AlertTriangle className="h-4 w-4" />
                          <AlertTitle>OTX AlienVault Error</AlertTitle>
                          <AlertDescription>{results.errors.otxAlienvault}</AlertDescription>
                        </Alert>
                      )}
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
