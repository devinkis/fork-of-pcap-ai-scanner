/**
 * VirusTotal API client for validating IOCs
 */

export interface VirusTotalResponse {
  data: {
    id: string
    type: string
    attributes: {
      last_analysis_stats: {
        harmless: number
        malicious: number
        suspicious: number
        undetected: number
        timeout: number
      }
      last_analysis_results: {
        [engine: string]: {
          category: string
          engine_name: string
          result: string | null
          method: string
          engine_version: string
        }
      }
      reputation: number
      total_votes: {
        harmless: number
        malicious: number
      }
      last_modification_date?: number
      last_analysis_date?: number
    }
  }
  error?: {
    code: string
    message: string
  }
}

export interface VirusTotalError {
  error: {
    code: string
    message: string
  }
}

class VirusTotalAPIError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public errorCode?: string,
  ) {
    super(message)
    this.name = "VirusTotalAPIError"
  }
}

async function makeVirusTotalRequest(url: string, apiKey: string): Promise<VirusTotalResponse> {
  const response = await fetch(url, {
    headers: {
      "x-apikey": apiKey,
      "User-Agent": "PCAP-Scanner/1.0",
    },
  })

  const data = await response.json()

  if (!response.ok) {
    if (response.status === 429) {
      throw new VirusTotalAPIError("Rate limit exceeded. Please wait before making more requests.", 429, "rate_limit")
    }
    if (response.status === 401) {
      throw new VirusTotalAPIError("Invalid API key", 401, "invalid_api_key")
    }
    if (response.status === 404) {
      throw new VirusTotalAPIError("Resource not found", 404, "not_found")
    }

    const errorMessage = data.error?.message || `VirusTotal API error: ${response.status} ${response.statusText}`
    throw new VirusTotalAPIError(errorMessage, response.status, data.error?.code)
  }

  return data
}

export async function checkIpAddress(apiKey: string, ip: string): Promise<VirusTotalResponse> {
  // Validate IP address format
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  if (!ipRegex.test(ip)) {
    throw new VirusTotalAPIError("Invalid IP address format", 400, "invalid_input")
  }

  return makeVirusTotalRequest(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, apiKey)
}

export async function checkDomain(apiKey: string, domain: string): Promise<VirusTotalResponse> {
  // Basic domain validation
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/
  if (!domainRegex.test(domain)) {
    throw new VirusTotalAPIError("Invalid domain format", 400, "invalid_input")
  }

  return makeVirusTotalRequest(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, apiKey)
}

export async function checkUrl(apiKey: string, url: string): Promise<VirusTotalResponse> {
  try {
    // Validate URL format
    new URL(url)
  } catch {
    throw new VirusTotalAPIError("Invalid URL format", 400, "invalid_input")
  }

  // Create URL identifier for VirusTotal
  const urlId = Buffer.from(url).toString("base64").replace(/=+$/, "")

  return makeVirusTotalRequest(`https://www.virustotal.com/api/v3/urls/${urlId}`, apiKey)
}

export async function checkFileHash(apiKey: string, hash: string): Promise<VirusTotalResponse> {
  // Validate hash format (MD5, SHA1, SHA256)
  const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/
  if (!hashRegex.test(hash)) {
    throw new VirusTotalAPIError(
      "Invalid hash format. Must be MD5 (32), SHA1 (40), or SHA256 (64) characters",
      400,
      "invalid_input",
    )
  }

  return makeVirusTotalRequest(`https://www.virustotal.com/api/v3/files/${hash.toLowerCase()}`, apiKey)
}

export function getDetectionRatio(stats: VirusTotalResponse["data"]["attributes"]["last_analysis_stats"]): string {
  const { malicious, suspicious } = stats
  const total = Object.values(stats).reduce((sum, count) => sum + count, 0)
  return `${malicious + suspicious}/${total}`
}

export function getThreatLevel(
  stats: VirusTotalResponse["data"]["attributes"]["last_analysis_stats"],
): "clean" | "suspicious" | "malicious" {
  const { malicious, suspicious } = stats
  const total = Object.values(stats).reduce((sum, count) => sum + count, 0)

  if (total === 0) return "clean"

  const detectionRate = (malicious + suspicious) / total

  if (detectionRate >= 0.1) return "malicious"
  if (detectionRate > 0) return "suspicious"
  return "clean"
}

export function getTopDetections(
  results: VirusTotalResponse["data"]["attributes"]["last_analysis_results"],
  limit = 10,
): Array<{ engine: string; category: string; result: string }> {
  return Object.entries(results)
    .filter(([_, result]) => result.category === "malicious" || result.category === "suspicious")
    .map(([engine, result]) => ({
      engine,
      category: result.category,
      result: result.result || "Detected",
    }))
    .slice(0, limit)
}
