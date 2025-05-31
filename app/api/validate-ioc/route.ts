// app/api/validate-ioc/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import * as VirusTotal from "@/lib/virustotal";
import * as MalwareBazaar from "@/lib/malwarebazaar";
import * as OTX from "@/lib/otx";
import * as AbuseIPDB from "@/lib/abuseipdb";
import * as Talos from "@/lib/talosintelligence";

export const runtime = 'nodejs';
interface ValidationRequest {
  type: "ip" | "domain" | "url" | "hash";
  value: string;
}

// Perbarui ValidationResponse untuk menyertakan hasil baru
interface ValidationResponse {
  ioc: {
    type: string;
    value: string;
  };
  results: {
    virusTotal?: VirusTotal.VirusTotalResponse["data"]["attributes"];
    malwareBazaar?: {
      detected: boolean;
      details: MalwareBazaar.MalwareBazaarResponse["data"][0] | null;
    };
    otxAlienvault?: OTX.OTXIndicatorDetails | { message: string };
    abuseIPDB?: AbuseIPDB.AbuseIPDBReport | { message: string }; // Menggunakan tipe yang benar
    talosIntelligence?: Talos.TalosReputation | { message: string };
  };
  errors?: {
    virusTotal?: string;
    malwareBazaar?: string;
    otxAlienvault?: string;
    abuseIPDB?: string;
    talosIntelligence?: string;
  };
}

export async function POST(request: NextRequest) {
  try {
    // Otentikasi bisa opsional jika Anda mau, tergantung kebutuhan
    const user = await getCurrentUser();
    // if (!user) {
    //   return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    // }

    const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
    const mbApiKey = process.env.MALWAREBAZAAR_API_KEY;
    const otxApiKey = process.env.OTX_API_KEY;
    const abuseIPDBApiKey = process.env.ABUSEIPDB_API_KEY;

    if (!vtApiKey) return NextResponse.json({ error: "VirusTotal API key not configured." }, { status: 500 });

    let requestData: ValidationRequest;
    try {
      requestData = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 });
    }

    const { type, value } = requestData;
    const trimmedValue = value.trim();

    if (!type || !trimmedValue || !["ip", "domain", "url", "hash"].includes(type)) {
      return NextResponse.json({ error: "Invalid or missing parameters: type and value" }, { status: 400 });
    }

    const response: ValidationResponse = {
      ioc: { type, value: trimmedValue },
      results: {},
      errors: {},
    };

    // VirusTotal Check
    try {
      let vtResultData: VirusTotal.VirusTotalResponse | null = null;
      switch (type) {
        case "ip": vtResultData = await VirusTotal.checkIpAddress(vtApiKey, trimmedValue); break;
        case "domain": vtResultData = await VirusTotal.checkDomain(vtApiKey, trimmedValue); break;
        case "url": vtResultData = await VirusTotal.checkUrl(vtApiKey, trimmedValue); break;
        case "hash": vtResultData = await VirusTotal.checkFileHash(vtApiKey, trimmedValue); break;
      }
      if (vtResultData?.data) {
        response.results.virusTotal = vtResultData.data.attributes;
      } else if (vtResultData?.error) {
        response.errors!.virusTotal = vtResultData.error.message;
      }
    } catch (error: any) {
      console.error("VirusTotal API error:", error);
      response.errors!.virusTotal = error.message || "Unknown VirusTotal error";
    }

    // MalwareBazaar Check (hanya untuk hash)
    if (type === "hash") {
      try {
        const mbResult = await MalwareBazaar.checkHash(mbApiKey || "", trimmedValue);
        if (mbResult.query_status === "ok" && mbResult.data.length > 0) {
            response.results.malwareBazaar = { detected: true, details: mbResult.data[0] };
        } else {
            response.results.malwareBazaar = { detected: false, details: null };
            if (mbResult.query_status !== "no_results" && mbResult.query_status !== "hash_not_found") {
                response.errors!.malwareBazaar = `MalwareBazaar: ${mbResult.query_status}`;
            }
        }
      } catch (error: any) {
        console.error("MalwareBazaar API error:", error);
        response.errors!.malwareBazaar = error.message || "Unknown MalwareBazaar error";
      }
    }

    // OTX AlienVault Check
    if (otxApiKey) {
      try {
        let otxResult: OTX.OTXIndicatorDetails | OTX.OTXError | null = null;
        switch (type) {
          case "ip": otxResult = await OTX.checkIpOTX(otxApiKey, trimmedValue); break;
          case "domain": otxResult = await OTX.checkDomainOTX(otxApiKey, trimmedValue); break;
          case "url": otxResult = await OTX.checkUrlOTX(otxApiKey, trimmedValue); break;
          case "hash": otxResult = await OTX.checkFileHashOTX(otxApiKey, trimmedValue); break;
        }
        if (otxResult) {
          if (OTX.isOTXError(otxResult)) {
            response.results.otxAlienvault = { message: otxResult.detail || otxResult.error || "OTX: Indicator not processed."};
            if (!otxResult.detail?.toLowerCase().includes("not found")) {
                 response.errors!.otxAlienvault = otxResult.detail || otxResult.error;
            }
          } else {
            response.results.otxAlienvault = otxResult;
          }
        }
      } catch (error: any) {
        console.error("OTX AlienVault API error:", error);
        response.errors!.otxAlienvault = error.message || "Unknown OTX AlienVault error";
      }
    } else {
      response.results.otxAlienvault = { message: "OTX API Key not configured. Skipping." };
    }

    // AbuseIPDB Check (hanya untuk IP)
    if (type === "ip" && abuseIPDBApiKey) {
      try {
        const abuseResult = await AbuseIPDB.checkIpAbuseIPDB(abuseIPDBApiKey, trimmedValue);
        if (AbuseIPDB.isAbuseIPDBError(abuseResult)) {
          response.results.abuseIPDB = { message: abuseResult.errors[0]?.detail || "AbuseIPDB: Error processing IP."};
          response.errors!.abuseIPDB = abuseResult.errors[0]?.detail || "AbuseIPDB error";
        } else {
          response.results.abuseIPDB = abuseResult as AbuseIPDB.AbuseIPDBReport; // Pastikan tipe benar
        }
      } catch (error: any) {
        console.error("AbuseIPDB API error:", error);
        response.errors!.abuseIPDB = error.message || "Unknown AbuseIPDB error";
      }
    } else if (type === "ip" && !abuseIPDBApiKey) {
        response.results.abuseIPDB = { message: "AbuseIPDB API Key not configured. Skipping." };
    }

    // Talos Intelligence Check (hanya untuk IP)
    if (type === "ip") {
      try {
        const talosResult = await Talos.getTalosReputation(trimmedValue);
        if (talosResult.errorMessage) {
          response.results.talosIntelligence = { message: talosResult.errorMessage };
          // Tidak selalu dianggap error fatal jika hanya scraping gagal
          // response.errors!.talosIntelligence = talosResult.errorMessage; 
        } else {
          response.results.talosIntelligence = talosResult;
        }
      } catch (error: any) {
        console.error("Talos Intelligence scraping error:", error);
        response.errors!.talosIntelligence = error.message || "Unknown Talos Intelligence error";
      }
    }

    if (Object.keys(response.errors || {}).length === 0) {
      delete response.errors;
    }

    return NextResponse.json(response);
  } catch (error: any) {
    console.error("Error validating IOC:", error);
    return NextResponse.json(
      { error: "Failed to validate IOC", details: error.message },
      { status: 500 },
    );
  }
}
