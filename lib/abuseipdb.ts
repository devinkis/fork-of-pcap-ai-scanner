// lib/abuseipdb.ts

export interface AbuseIPDBReport {
  ipAddress: string;
  isPublic: boolean;
  ipVersion: number;
  isWhitelisted: boolean | null;
  abuseConfidenceScore: number;
  countryCode: string | null;
  countryName: string | null;
  usageType: string | null;
  isp: string;
  domain: string | null;
  hostnames: string[];
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
}

export interface AbuseIPDBError {
  errors: Array<{
    detail: string;
    status: number;
    source?: { parameter: string };
  }>;
}

class AbuseIPDBAPIError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public apiErrors?: AbuseIPDBError["errors"],
  ) {
    super(message);
    this.name = "AbuseIPDBAPIError";
  }
}

export async function checkIpAbuseIPDB(apiKey: string, ip: string, maxAgeInDays: number = 90): Promise<AbuseIPDBReport | AbuseIPDBError> {
  if (!apiKey) {
    throw new AbuseIPDBAPIError("AbuseIPDB API Key is required.", 401);
  }

  const url = `https://api.abuseipdb.com/api/v2/check`;

  try {
    const response = await fetch(url + `?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=${maxAgeInDays}&verbose`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Key': apiKey,
        'User-Agent': 'PCAP-Scanner/1.0 (Your Contact Email/Website)', // Ganti dengan info Anda
      },
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("AbuseIPDB API Error Response:", data);
      throw new AbuseIPDBAPIError(
        data.errors?.[0]?.detail || `AbuseIPDB API error: ${response.status}`,
        response.status,
        data.errors
      );
    }
    return data.data as AbuseIPDBReport;
  } catch (error) {
    if (error instanceof AbuseIPDBAPIError) throw error;
    console.error("Error fetching from AbuseIPDB:", error);
    throw new AbuseIPDBAPIError("Failed to connect to AbuseIPDB API.", 500);
  }
}

export function isAbuseIPDBError(response: any): response is AbuseIPDBError {
  return response && Array.isArray(response.errors) && response.errors.length > 0;
}
