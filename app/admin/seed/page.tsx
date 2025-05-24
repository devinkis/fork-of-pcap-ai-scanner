"use client"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Loader2, CheckCircle, AlertTriangle } from "lucide-react"

export default function SeedPage() {
  const [seedKey, setSeedKey] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState("")

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!seedKey.trim()) {
      setError("Please enter a seed key")
      return
    }

    setLoading(true)
    setError("")
    setResult(null)

    try {
      const response = await fetch("/api/admin/seed", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ seedKey: seedKey.trim() }),
      })

      const data = await response.json()

      if (response.ok) {
        setResult(data)
      } else {
        setError(data.error || "Failed to seed database")
      }
    } catch (err) {
      setError("An error occurred while seeding the database")
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="container mx-auto py-10 px-4">
      <div className="max-w-md mx-auto">
        <Card>
          <CardHeader>
            <CardTitle>Database Seeding</CardTitle>
            <CardDescription>Initialize the database with default users</CardDescription>
          </CardHeader>
          <CardContent>
            {!result ? (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <Label htmlFor="seedKey">Seed Key</Label>
                  <Input
                    id="seedKey"
                    type="password"
                    value={seedKey}
                    onChange={(e) => setSeedKey(e.target.value)}
                    placeholder="Enter the seed key"
                    disabled={loading}
                    required
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    This key is required to initialize the database securely.
                  </p>
                </div>

                {error && (
                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}

                <div className="bg-muted/50 p-4 rounded-lg">
                  <p className="text-sm mb-2">This will create the following default users:</p>
                  <ul className="list-disc pl-5 space-y-1 text-sm">
                    <li>
                      <strong>Admin:</strong> admin@pcapscanner.com / admin123
                    </li>
                    <li>
                      <strong>User:</strong> user@pcapscanner.com / user123
                    </li>
                  </ul>
                  <p className="text-xs text-muted-foreground mt-2">
                    Note: If these users already exist, their passwords will not be changed.
                  </p>
                </div>

                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Seeding Database...
                    </>
                  ) : (
                    "Seed Database"
                  )}
                </Button>
              </form>
            ) : (
              <div className="space-y-4">
                <Alert>
                  <CheckCircle className="h-4 w-4" />
                  <AlertDescription>{result.message}</AlertDescription>
                </Alert>

                {result.users && result.users.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Created/Updated Users:</h4>
                    <div className="space-y-2">
                      {result.users.map((user: any, index: number) => (
                        <div key={index} className="bg-muted/50 p-2 rounded text-sm">
                          <div>
                            <strong>Email:</strong> {user.email}
                          </div>
                          <div>
                            <strong>Role:</strong> {user.role}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                  <h4 className="text-sm font-medium text-green-800 mb-2">Next Steps:</h4>
                  <ol className="list-decimal pl-5 space-y-1 text-sm text-green-700">
                    <li>
                      Go to the{" "}
                      <a href="/login" className="underline">
                        login page
                      </a>
                    </li>
                    <li>Use the credentials shown above to log in</li>
                    <li>Start uploading and analyzing PCAP files</li>
                  </ol>
                </div>

                <Button
                  onClick={() => {
                    setResult(null)
                    setSeedKey("")
                    setError("")
                  }}
                  variant="outline"
                  className="w-full"
                >
                  Seed Again
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </main>
  )
}
