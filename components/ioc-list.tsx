"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { AlertTriangle, Search, ExternalLink, EyeOff } from "lucide-react"
import { IOCValidator } from "@/components/ioc-validator"

interface IOC {
  type: "ip" | "domain" | "url" | "hash"
  value: string
  context: string
  confidence: number
}

interface IOCListProps {
  iocs: IOC[]
}

export function IOCList({ iocs }: IOCListProps) {
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null)
  const [showValidator, setShowValidator] = useState<boolean>(false)

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "ip":
        return "🌐"
      case "domain":
        return "🔗"
      case "url":
        return "🔍"
      case "hash":
        return "🔒"
      default:
        return "❓"
    }
  }

  const getConfidenceBadge = (confidence: number) => {
    if (confidence >= 80) {
      return <Badge className="bg-red-100 text-red-800">High ({confidence}%)</Badge>
    } else if (confidence >= 50) {
      return <Badge className="bg-yellow-100 text-yellow-800">Medium ({confidence}%)</Badge>
    } else {
      return <Badge className="bg-blue-100 text-blue-800">Low ({confidence}%)</Badge>
    }
  }

  const handleValidate = (ioc: IOC) => {
    setSelectedIOC(ioc)
    setShowValidator(true)
  }

  const handleCloseValidator = () => {
    setShowValidator(false)
    setSelectedIOC(null)
  }

  const getExternalLink = (ioc: IOC) => {
    const encodedValue = encodeURIComponent(ioc.value)
    switch (ioc.type) {
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

  const truncateValue = (value: string, maxLength = 50) => {
    if (value.length <= maxLength) return value
    return value.substring(0, maxLength) + "..."
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Indicators of Compromise</CardTitle>
              <CardDescription>Potential IOCs extracted from network traffic</CardDescription>
            </div>
            {showValidator && (
              <Button variant="outline" onClick={handleCloseValidator}>
                <EyeOff className="h-4 w-4 mr-2" />
                Hide Validator
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {iocs.length > 0 ? (
            <div className="rounded-md border overflow-hidden">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[100px]">Type</TableHead>
                      <TableHead className="min-w-[200px]">Value</TableHead>
                      <TableHead className="min-w-[150px]">Context</TableHead>
                      <TableHead className="w-[120px]">Confidence</TableHead>
                      <TableHead className="w-[200px]">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {iocs.map((ioc, index) => (
                      <TableRow key={index} className="hover:bg-muted/50">
                        <TableCell>
                          <div className="flex items-center">
                            <span className="mr-2 text-lg">{getTypeIcon(ioc.type)}</span>
                            <span className="capitalize font-medium">{ioc.type}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="font-mono text-sm">
                            <span title={ioc.value}>{truncateValue(ioc.value)}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <span className="text-sm">{ioc.context}</span>
                        </TableCell>
                        <TableCell>{getConfidenceBadge(ioc.confidence)}</TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button variant="outline" size="sm" onClick={() => handleValidate(ioc)}>
                              <Search className="h-4 w-4 mr-1" />
                              Validate
                            </Button>
                            <Button variant="outline" size="sm" asChild>
                              <a
                                href={getExternalLink(ioc)}
                                target="_blank"
                                rel="noopener noreferrer"
                                title="View on VirusTotal"
                              >
                                <ExternalLink className="h-4 w-4 mr-1" />
                                VT
                              </a>
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <AlertTriangle className="h-16 w-16 text-muted-foreground mb-4" />
              <h3 className="text-lg font-medium mb-2">No IOCs Detected</h3>
              <p className="text-muted-foreground max-w-md">
                No indicators of compromise were found in the network traffic analysis. This could indicate clean
                traffic or the need for more advanced detection techniques.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {showValidator && selectedIOC && (
        <IOCValidator
          defaultIoc={{
            type: selectedIOC.type,
            value: selectedIOC.value,
          }}
          onValidationComplete={(results) => {
            console.log("Validation completed:", results)
            // You can add additional logic here if needed
          }}
        />
      )}
    </div>
  )
}
