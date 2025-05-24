"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Loader2 } from "lucide-react"

export function LoginForm() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState(false)
  const [callbackUrl, setCallbackUrl] = useState("/")
  const router = useRouter()
  const searchParams = useSearchParams()

  useEffect(() => {
    // Get the callback URL from search params
    const callback = searchParams?.get("callbackUrl") || "/"
    setCallbackUrl(callback)

    // Check for error parameter
    const errorParam = searchParams?.get("error")
    if (errorParam === "session_expired") {
      setError("Your session has expired. Please log in again.")
    }
  }, [searchParams])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!email.trim() || !password.trim()) {
      setError("Email and password are required")
      return
    }

    setLoading(true)
    setError("")
    setSuccess(false)

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: email.trim(),
          password: password,
        }),
        credentials: "include", // Ensure cookies are included
      })

      const data = await response.json()

      if (response.ok && data.success) {
        setSuccess(true)

        // Wait a moment for cookies to be set
        await new Promise((resolve) => setTimeout(resolve, 500))

        // Hard redirect to ensure cookies are properly set
        window.location.href = callbackUrl || "/"
      } else {
        setError(data.error || "Login failed")
      }
    } catch (error) {
      setError("Network error. Please check your connection and try again.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      {success ? (
        <div className="space-y-4">
          <Alert className="bg-green-50 border-green-200">
            <AlertDescription className="text-green-800">Login successful! Redirecting you...</AlertDescription>
          </Alert>
          <div className="flex justify-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
          <div className="text-center">
            <Button variant="link" onClick={() => (window.location.href = callbackUrl)} type="button">
              Click here if you are not redirected automatically
            </Button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
              autoComplete="email"
              placeholder="Enter your email"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
              autoComplete="current-password"
              placeholder="Enter your password"
            />
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Signing in...
              </>
            ) : (
              "Sign in"
            )}
          </Button>
        </form>
      )}

      <div className="text-sm text-muted-foreground text-center">
        <p>Contact your administrator if you need access</p>
      </div>
    </div>
  )
}
