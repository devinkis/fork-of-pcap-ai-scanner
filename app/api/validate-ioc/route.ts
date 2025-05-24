import { type NextRequest, NextResponse } from "next/server"
import { getCurrentUser } from "@/lib/auth"
import * as VirusTotal from "@/lib/virustotal"
import * as MalwareBazaar from "@/lib/malwarebazaar"

interface ValidationRequest {
  type: "ip" | "domain" | "url" | "hash"
  value: string
}

interface ValidationResponse {
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

export async function POST(request: NextRequest) {
  try {
    // Ensure user is authenticated
    const user = await getCurrentUser()
    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    // Get API keys from environment variables
    const vtApiKey = process.env.VIRUSTOTAL_API_KEY
    const mbApiKey = process.env.MALWAREBAZAAR_API_KEY

    if (!vtApiKey) {
      return NextResponse.json(
        { error: "VirusTotal API key not configured. Please set VIRUSTOTAL_API_KEY environment variable." },
        { status: 500 },
      )
    }

    // Parse and validate request body
    let requestData: ValidationRequest
    try {
      requestData = await request.json()
    } catch {
      return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 })
    }

    const { type, value } = requestData

    if (!type || !value) {
      return NextResponse.json({ error: "Missing required parameters: type and value" }, { status: 400 })
    }

    if (!["ip", "domain", "url", "hash"].includes(type)) {
      return NextResponse.json({ error: "Invalid IOC type. Supported types: ip, domain, url, hash" }, { status: 400 })
    }

    const trimmedValue = value.trim()
    if (!trimmedValue) {
      return NextResponse.json({ error: "IOC value cannot be empty" }, { status: 400 })
    }

    // Prepare the response
    const response: ValidationResponse = {
      ioc: {
        type,
        value: trimmedValue,
      },
      results: {},
      errors: {},
    }

    // Check with VirusTotal
    try {
      let vtResult: VirusTotal.VirusTotalResponse | null = null

      switch (type) {
        case "ip":
          vtResult = await VirusTotal.checkIpAddress(vtApiKey, trimmedValue)
          break
        case "domain":
          vtResult = await VirusTotal.checkDomain(vtApiKey, trimmedValue)
          break
        case "url":
          vtResult = await VirusTotal.checkUrl(vtApiKey, trimmedValue)
          break
        case "hash":
          vtResult = await VirusTotal.checkFileHash(vtApiKey, trimmedValue)
          break
      }

      if (vtResult && vtResult.data) {
        const stats = vtResult.data.attributes.last_analysis_stats
        const engines = VirusTotal.getTopDetections(vtResult.data.attributes.last_analysis_results)

        response.results.virusTotal = {
          detectionRatio: VirusTotal.getDetectionRatio(stats),
          threatLevel: VirusTotal.getThreatLevel(stats),
          engines: engines.map((engine) => ({
            name: engine.engine,
            category: engine.category,
            result: engine.result,
          })),
          lastAnalysisDate: vtResult.data.attributes.last_analysis_date
            ? new Date(vtResult.data.attributes.last_analysis_date * 1000).toISOString()
            : undefined,
          reputation: vtResult.data.attributes.reputation,
        }
      }
    } catch (error) {
      console.error("VirusTotal API error:", error)
      if (error instanceof Error) {
        response.errors!.virusTotal = error.message
      } else {
        response.errors!.virusTotal = "Unknown error occurred while checking with VirusTotal"
      }
    }

    // Check with MalwareBazaar for file hashes
    if (type === "hash") {
      try {
        const mbResult = await MalwareBazaar.checkHash(mbApiKey || "", trimmedValue)
        const isMalicious = MalwareBazaar.isMalicious(mbResult)
        const details = MalwareBazaar.getMalwareDetails(mbResult)

        response.results.malwareBazaar = {
          detected: isMalicious,
          details: details,
        }
      } catch (error) {
        console.error("MalwareBazaar API error:", error)
        if (error instanceof Error) {
          response.errors!.malwareBazaar = error.message
        } else {
          response.errors!.malwareBazaar = "Unknown error occurred while checking with MalwareBazaar"
        }
      }
    }

    // Clean up empty errors object
    if (response.errors && Object.keys(response.errors).length === 0) {
      delete response.errors
    }

    return NextResponse.json(response)
  } catch (error) {
    console.error("Error validating IOC:", error)
    return NextResponse.json(
      {
        error: "Failed to validate IOC",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
