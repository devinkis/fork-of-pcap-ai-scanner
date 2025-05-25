// app/api/validate-ioc/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import * as VirusTotal from "@/lib/virustotal";
import * as MalwareBazaar from "@/lib/malwarebazaar";
// --- TAMBAHKAN IMPOR INI ---
import * as OTX from "@/lib/otx";
// --- SELESAI PENAMBAHAN ---

interface ValidationRequest {
  type: "ip" | "domain" | "url" | "hash";
  value: string;
}

interface ValidationResponse {
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
    otxAlienvault?: OTX.OTXIndicatorDetails | { message: string }; // Bisa hasil atau pesan error sederhana
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

export async function POST(request: NextRequest) {
  try {
    const user = await getCurrentUser();
    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    }

    const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
    const mbApiKey = process.env.MALWAREBAZAAR_API_KEY;
    // --- TAMBAHKAN INI ---
    const otxApiKey = process.env.OTX_API_KEY;
    // --- SELESAI PENAMBAHAN ---

    if (!vtApiKey) {
      return NextResponse.json(
        { error: "VirusTotal API key not configured." },
        { status: 500 },
      );
    }
    // OTX API Key juga penting
    if (!otxApiKey) {
      console.warn("OTX_API_KEY is not configured. OTX lookups will be skipped.");
      // Tidak perlu return error, biarkan fitur lain berjalan
    }


    let requestData: ValidationRequest;
    try {
      requestData = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 });
    }

    const { type, value } = requestData;

    if (!type || !value) {
      return NextResponse.json({ error: "Missing required parameters: type and value" }, { status: 400 });
    }
    if (!["ip", "domain", "url", "hash"].includes(type)) {
      return NextResponse.json({ error: "Invalid IOC type." }, { status: 400 });
    }
    const trimmedValue = value.trim();
    if (!trimmedValue) {
      return NextResponse.json({ error: "IOC value cannot be empty" }, { status: 400 });
    }

    const response: ValidationResponse = {
      ioc: { type, value: trimmedValue },
      results: {},
      errors: {},
    };

    // VirusTotal Check (tetap sama)
    try {
      let vtResult: VirusTotal.VirusTotalResponse | null = null;
      switch (type) {
        case "ip": vtResult = await VirusTotal.checkIpAddress(vtApiKey, trimmedValue); break;
        case "domain": vtResult = await VirusTotal.checkDomain(vtApiKey, trimmedValue); break;
        case "url": vtResult = await VirusTotal.checkUrl(vtApiKey, trimmedValue); break;
        case "hash": vtResult = await VirusTotal.checkFileHash(vtApiKey, trimmedValue); break;
      }
      if (vtResult && vtResult.data) {
        const stats = vtResult.data.attributes.last_analysis_stats;
        response.results.virusTotal = {
          detectionRatio: VirusTotal.getDetectionRatio(stats),
          threatLevel: VirusTotal.getThreatLevel(stats),
          engines: VirusTotal.getTopDetections(vtResult.data.attributes.last_analysis_results).map(e => ({ name: e.engine, category: e.category, result: e.result })),
          lastAnalysisDate: vtResult.data.attributes.last_analysis_date ? new Date(vtResult.data.attributes.last_analysis_date * 1000).toISOString() : undefined,
          reputation: vtResult.data.attributes.reputation,
        };
      }
    } catch (error: any) {
      console.error("VirusTotal API error:", error);
      response.errors!.virusTotal = error.message || "Unknown VirusTotal error";
    }

    // MalwareBazaar Check (tetap sama, hanya untuk hash)
    if (type === "hash") {
      try {
        const mbResult = await MalwareBazaar.checkHash(mbApiKey || "", trimmedValue);
        response.results.malwareBazaar = {
          detected: MalwareBazaar.isMalicious(mbResult),
          details: MalwareBazaar.getMalwareDetails(mbResult),
        };
      } catch (error: any) {
        console.error("MalwareBazaar API error:", error);
        response.errors!.malwareBazaar = error.message || "Unknown MalwareBazaar error";
      }
    }

    // --- TAMBAHKAN OTX ALIENVAULT CHECK ---
    if (otxApiKey) { // Hanya jalankan jika API Key OTX ada
      try {
        let otxResult: OTX.OTXIndicatorDetails | OTX.OTXError | null = null;
        switch (type) {
          case "ip":
            otxResult = await OTX.checkIpOTX(otxApiKey, trimmedValue);
            break;
          case "domain":
            otxResult = await OTX.checkDomainOTX(otxApiKey, trimmedValue);
            break;
          case "url":
            otxResult = await OTX.checkUrlOTX(otxApiKey, trimmedValue);
            break;
          case "hash":
            otxResult = await OTX.checkFileHashOTX(otxApiKey, trimmedValue);
            break;
        }

        if (otxResult) {
          if (OTX.isOTXError(otxResult)) {
            // Jika OTX mengembalikan pesan error (misalnya, not found), tampilkan sebagai pesan
            response.results.otxAlienvault = { message: otxResult.detail || otxResult.error || "Indicator not found or error in OTX." };
            if (otxResult.detail?.includes("not found")) {
                 // Tidak dianggap error fatal jika hanya "not found"
            } else {
                response.errors!.otxAlienvault = otxResult.detail || otxResult.error || "OTX error";
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
      response.results.otxAlienvault = { message: "OTX API Key not configured. Skipping OTX lookup." };
    }
    // --- SELESAI OTX CHECK ---

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
