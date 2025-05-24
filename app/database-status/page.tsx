"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { CheckCircle, XCircle, AlertTriangle, RefreshCw } from "lucide-react"

export default function DatabaseStatusPage() {
  const [status, setStatus] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  const loadStatus = async () => {
    setLoading(true)
    setError("")

    try {
      const response = await fetch("/api/health")
      const data = await response.json()
      setStatus(data)
    } catch (err) {
      setError("Failed to load database status")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadStatus()
  }, [])

  const getStatusIcon = (isOk: boolean) => {
    return isOk ? <CheckCircle className="h-5 w-5 text-green-500" /> : <XCircle className="h-5 w-5 text-red-500" />
  }

  const getStatusBadge = (isOk: boolean, label: string) => {
    return (
      <Badge className={isOk ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}>
        {isOk ? "✅" : "❌"} {label}
      </Badge>
    )
  }

  return (
    <div className="container mx-auto py-10 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold">Database Status</h1>
            <p className="text-muted-foreground">Check your database connection and configuration</p>
          </div>
          <Button onClick={loadStatus} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {error && (
          <Alert variant="destructive" className="mb-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {status && (
          <div className="space-y-6">
            {/* Overall Status */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  {getStatusIcon(status.status === "ok")}
                  Overall Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{status.status === "ok" ? "✅ Healthy" : "❌ Issues Detected"}</div>
                <p className="text-muted-foreground mt-1">Database: {status.database}</p>
              </CardContent>
            </Card>

            {/* Environment Configuration */}
            <Card>
              <CardHeader>
                <CardTitle>Environment Configuration</CardTitle>
                <CardDescription>Required environment variables</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  {status.config &&
                    Object.entries(status.config).map(([key, value]: [string, any]) => (
                      <div key={key} className="flex items-center justify-between p-2 border rounded">
                        <span className="text-sm font-medium">
                          {key.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase())}
                        </span>
                        {getStatusBadge(value, value ? "Set" : "Missing")}
                      </div>
                    ))}
                </div>
              </CardContent>
            </Card>

            {/* Database Schema */}
            {status.schema && (
              <Card>
                <CardHeader>
                  <CardTitle>Database Schema</CardTitle>
                  <CardDescription>Database tables and data</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="flex items-center justify-between p-2 border rounded">
                        <span className="text-sm font-medium">Users Table</span>
                        {getStatusBadge(status.schema.usersTable, status.schema.usersTable ? "Exists" : "Missing")}
                      </div>
                      <div className="flex items-center justify-between p-2 border rounded">
                        <span className="text-sm font-medium">PCAP Files Table</span>
                        {getStatusBadge(
                          status.schema.pcapFilesTable,
                          status.schema.pcapFilesTable ? "Exists" : "Missing",
                        )}
                      </div>
                      <div className="flex items-center justify-between p-2 border rounded">
                        <span className="text-sm font-medium">User Count</span>
                        <Badge className="bg-blue-100 text-blue-800">{status.schema.userCount || 0} users</Badge>
                      </div>
                    </div>

                    {status.schema.needsSeeding && (
                      <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>
                          Database is empty and needs to be seeded with initial users.
                          <Button className="ml-2" size="sm" onClick={() => (window.location.href = "/admin/seed")}>
                            Seed Database
                          </Button>
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Next Steps */}
            {(status.nextSteps || status.suggestions || status.troubleshooting) && (
              <Card>
                <CardHeader>
                  <CardTitle>{status.status === "ok" ? "Next Steps" : "Troubleshooting"}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {(status.nextSteps || status.suggestions || status.troubleshooting || []).map(
                      (step: string, index: number) => (
                        <div key={index} className="flex items-start gap-2">
                          <span className="text-sm font-medium text-muted-foreground">{index + 1}.</span>
                          <span className="text-sm">{step}</span>
                        </div>
                      ),
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Raw Status Data */}
            <details className="mt-6">
              <summary className="cursor-pointer font-medium mb-2">Raw Status Data</summary>
              <pre className="text-xs overflow-auto p-4 bg-black text-white rounded max-h-96">
                {JSON.stringify(status, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </div>
    </div>
  )
}
