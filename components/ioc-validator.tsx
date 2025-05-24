"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Loader2, AlertTriangle, Shield, CheckCircle, XCircle, Clock, ExternalLink } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface IOCValidatorProps {
  defaultIoc?: {
    type: string
    value: string
  }
  onValidationComplete?: (results: any) => void
}

interface ValidationResult {
  ioc: {
    type: string
    value: string
  }
  results: {
    virusTotal?: {
      detectionRatio: string
      threatLevel: "clean" | "suspicious" | "malicious"
      engines: Array<{
        name: string
        category: string
        result: string
      }>
      lastAnalysisDate?: string
      reputation?: number
    }
    malwareBazaar?: {
      detected: boolean
      details: {
        fileName: string
        fileType: string
        fileSize: number
        firstSeen: string
        lastSeen: string
        tags: string[]
        signature: string | null
        reporter: string
        deliveryMethod: string
      } | null
    }
  }
  errors?: {
    virusTotal?: string
    malwareBazaar?: string
  }
}

export function IOCValidator({ defaultIoc, onValidationComplete }: IOCValidatorProps) {
  const [iocType, setIocType] = useState<string>(defaultIoc?.type || "ip")
  const [iocValue, setIocValue] = useState<string>(defaultIoc?.value || "")
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<ValidationResult | null>(null)

  const validateIOC = async () => {
    if (!iocValue.trim()) {
      setError("Please enter a value to validate")
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)

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
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`)
      }

      setResults(data)
      if (onValidationComplete) {
        onValidationComplete(data)
      }
    } catch (err) {
      console.error("Validation error:", err)
      setError(err instanceof Error ? err.message : "An error occurred during validation")
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !loading) {
      validateIOC()
    }
  }

  const getThreatLevelBadge = (threatLevel: string) => {
    switch (threatLevel) {
      case "malicious":
        return (
          <Badge className="bg-red-100 text-red-800">
            <XCircle className="h-3 w-3 mr-1" />
            Malicious
          </Badge>
        )
      case "suspicious":
        return (
          <Badge className="bg-yellow-100 text-yellow-800">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Suspicious
          </Badge>
        )
      case "clean":
        return (
          <Badge className="bg-green-100 text-green-800">
            <CheckCircle className="h-3 w-3 mr-1" />
            Clean
          </Badge>
        )
      default:
        return (
          <Badge className="bg-gray-100 text-gray-800">
            <Clock className="h-3 w-3 mr-1" />
            Unknown
          </Badge>
        )
    }
  }

  const getPlaceholder = (type: string) => {
    switch (type) {
      case "ip":
        return "e.g., 8.8.8.8"
      case "domain":
        return "e.g., example.com"
      case "url":
        return "e.g., https://example.com/path"
      case "hash":
        return "e.g., 44d88612fea8a8f36de82e1278abb02f"
      default:
        return "Enter value to validate"
    }
  }

  const getExternalLink = (type: string, value: string) => {
    const encodedValue = encodeURIComponent(value)
    switch (type) {
      case "ip":
        return `https://www.virustotal.com/gui/ip-address/${encodedValue}`
      case "domain":
        return `https://www.virustotal.com/gui/domain/${encodedValue}`
      case "url":
        return `https://www.virustotal.com/gui/url/${encodedValue}`
      case "hash":
        return `https://www.virustotal.com/gui/file/${encodedValue}`
      default:
        return "#"
    }
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes"
    const k = 1024
    const sizes = ["Bytes", "KB", "MB", "GB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i]
  }

  const formatDate = (dateString: string): string => {
    try {
      return new Date(dateString).toLocaleString()
    } catch {
      return dateString
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>IOC Validator</CardTitle>
        <CardDescription>Validate indicators of compromise using VirusTotal and MalwareBazaar</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
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
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium">
                  Results for {results.ioc.type}: <span className="font-bold font-mono">{results.ioc.value}</span>
                </h3>
                <Button variant="outline" size="sm" asChild>
                  <a
                    href={getExternalLink(results.ioc.type, results.ioc.value)}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <ExternalLink className="h-4 w-4 mr-1" />
                    View on VirusTotal
                  </a>
                </Button>
              </div>

              <Tabs defaultValue="virustotal">
                <TabsList>
                  <TabsTrigger value="virustotal">VirusTotal</TabsTrigger>
                  {results.results.malwareBazaar && <TabsTrigger value="malwarebazaar">MalwareBazaar</TabsTrigger>}
                  {results.errors && Object.keys(results.errors).length > 0 && (
                    <TabsTrigger value="errors">Errors</TabsTrigger>
                  )}
                </TabsList>

                <TabsContent value="virustotal" className="pt-4">
                  {results.results.virusTotal ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center">
                          <div
                            className={`p-2 rounded-full mr-3 ${
                              results.results.virusTotal.threatLevel === "malicious"
                                ? "bg-red-100"
                                : results.results.virusTotal.threatLevel === "suspicious"
                                  ? "bg-yellow-100"
                                  : "bg-green-100"
                            }`}
                          >
                            {results.results.virusTotal.threatLevel === "malicious" ? (
                              <XCircle className="h-5 w-5 text-red-600" />
                            ) : results.results.virusTotal.threatLevel === "suspicious" ? (
                              <AlertTriangle className="h-5 w-5 text-yellow-600" />
                            ) : (
                              <CheckCircle className="h-5 w-5 text-green-600" />
                            )}
                          </div>
                          <div>
                            <div className="font-medium">Threat Assessment</div>
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

                      {results.results.virusTotal.reputation !== undefined && (
                        <div className="p-3 bg-muted/50 rounded-md">
                          <div className="text-sm font-medium">Community Reputation</div>
                          <div className="text-lg font-bold">{results.results.virusTotal.reputation}</div>
                        </div>
                      )}

                      {results.results.virusTotal.engines && results.results.virusTotal.engines.length > 0 && (
                        <div>
                          <h4 className="text-sm font-medium mb-2">Detection Details</h4>
                          <div className="border rounded-md overflow-hidden">
                            <div className="max-h-64 overflow-y-auto">
                              <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50 sticky top-0">
                                  <tr>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                      Engine
                                    </th>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                      Category
                                    </th>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                      Result
                                    </th>
                                  </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                  {results.results.virusTotal.engines.map((engine, index) => (
                                    <tr key={index}>
                                      <td className="px-4 py-2 whitespace-nowrap text-sm font-medium">{engine.name}</td>
                                      <td className="px-4 py-2 whitespace-nowrap text-sm">
                                        <Badge
                                          className={
                                            engine.category === "malicious"
                                              ? "bg-red-100 text-red-800"
                                              : "bg-yellow-100 text-yellow-800"
                                          }
                                        >
                                          {engine.category}
                                        </Badge>
                                      </td>
                                      <td className="px-4 py-2 whitespace-nowrap text-sm">{engine.result}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-4 text-muted" />
                      <p>No results from VirusTotal</p>
                      <p className="text-sm">
                        The IOC may not be in their database or there was an error with the API.
                      </p>
                    </div>
                  )}
                </TabsContent>

                {results.results.malwareBazaar && (
                  <TabsContent value="malwarebazaar" className="pt-4">
                    {results.results.malwareBazaar.detected && results.results.malwareBazaar.details ? (
                      <div className="space-y-4">
                        <Alert variant="destructive">
                          <Shield className="h-4 w-4" />
                          <AlertTitle>Malware Detected!</AlertTitle>
                          <AlertDescription>
                            This hash has been identified as malware in the MalwareBazaar database.
                          </AlertDescription>
                        </Alert>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <div className="text-sm font-medium">File Name</div>
                            <div className="text-sm bg-gray-100 p-2 rounded font-mono">
                              {results.results.malwareBazaar.details.fileName}
                            </div>
                          </div>
                          <div className="space-y-2">
                            <div className="text-sm font-medium">File Type</div>
                            <div className="text-sm bg-gray-100 p-2 rounded">
                              {results.results.malwareBazaar.details.fileType}
                            </div>
                          </div>
                          <div className="space-y-2">
                            <div className="text-sm font-medium">File Size</div>
                            <div className="text-sm bg-gray-100 p-2 rounded">
                              {formatFileSize(results.results.malwareBazaar.details.fileSize)}
                            </div>
                          </div>
                          <div className="space-y-2">
                            <div className="text-sm font-medium">First Seen</div>
                            <div className="text-sm bg-gray-100 p-2 rounded">
                              {formatDate(results.results.malwareBazaar.details.firstSeen)}
                            </div>
                          </div>
                          <div className="space-y-2">
                            <div className="text-sm font-medium">Last Seen</div>
                            <div className="text-sm bg-gray-100 p-2 rounded">
                              {formatDate(results.results.malwareBazaar.details.lastSeen)}
                            </div>
                          </div>
                          <div className="space-y-2">
                            <div className="text-sm font-medium">Reporter</div>
                            <div className="text-sm bg-gray-100 p-2 rounded">
                              {results.results.malwareBazaar.details.reporter}
                            </div>
                          </div>
                        </div>

                        {results.results.malwareBazaar.details.signature && (
                          <div className="space-y-2">
                            <div className="text-sm font-medium">Signature</div>
                            <div className="text-sm bg-gray-100 p-2 rounded font-mono">
                              {results.results.malwareBazaar.details.signature}
                            </div>
                          </div>
                        )}

                        <div className="space-y-2">
                          <div className="text-sm font-medium">Delivery Method</div>
                          <div className="text-sm bg-gray-100 p-2 rounded">
                            {results.results.malwareBazaar.details.deliveryMethod}
                          </div>
                        </div>

                        {results.results.malwareBazaar.details.tags.length > 0 && (
                          <div className="space-y-2">
                            <div className="text-sm font-medium">Tags</div>
                            <div className="flex flex-wrap gap-2">
                              {results.results.malwareBazaar.details.tags.map((tag, index) => (
                                <Badge key={index} className="bg-red-100 text-red-800">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-500" />
                        <p>No malware detected</p>
                        <p className="text-sm">This hash was not found in the MalwareBazaar database.</p>
                      </div>
                    )}
                  </TabsContent>
                )}

                {results.errors && Object.keys(results.errors).length > 0 && (
                  <TabsContent value="errors" className="pt-4">
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
                    </div>
                  </TabsContent>
                )}
              </Tabs>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
