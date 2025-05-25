// lib/otx.ts

export interface OTXIndicatorDetails {
  indicator: string;
  type: string;
  description?: string;
  title?: string;
  references?: string[];
  malware_families?: string[];
  tags?: string[];
  pulse_info?: {
    count: number;
    pulses: Array<{
      id: string;
      name: string;
      tags: string[];
      created: string;
      adversary?: string;
    }>;
  };
  // Tambahkan field lain yang relevan dari respons OTX
}

export interface OTXError {
  detail?: string;
  error?: string;
}

class OTXAPIError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public otxError?: OTXError,
  ) {
    super(message);
    this.name = "OTXAPIError";
  }
}

async function makeOTXRequest(apiKey: string, endpoint: string): Promise<any> {
  const baseUrl = "https://otx.alienvault.com/api/v1";
  const url = `${baseUrl}/${endpoint}`;

  const response = await fetch(url, {
    headers: {
      "X-OTX-API-KEY": apiKey,
      "User-Agent": "PCAP-Scanner/1.0", // Ganti dengan User-Agent yang sesuai
    },
  });

  const data = await response.json();

  if (!response.ok) {
    const errorMessage = data.detail || data.error || `OTX API error: ${response.status} ${response.statusText}`;
    console.error("OTX API Error Response:", data);
    throw new OTXAPIError(errorMessage, response.status, data);
  }
  return data;
}

// Fungsi untuk mendapatkan detail indikator berdasarkan tipenya
async function getIndicatorDetails(
  apiKey: string,
  indicatorType: "ip" | "domain" | "hostname" | "url" | "file", // Tipe yang didukung OTX
  indicatorValue: string,
  section: string = "general" // Contoh: general, geo, malware, url_list, passive_dns
): Promise<OTXIndicatorDetails | OTXError> {
  if (!apiKey) {
    throw new OTXAPIError("OTX API Key is required.", 401);
  }

  let otxTypePath: string;
  switch (indicatorType) {
    case "ip":
      otxTypePath = `indicators/IPv4/${encodeURIComponent(indicatorValue)}/${section}`;
      break;
    case "domain":
      otxTypePath = `indicators/domain/${encodeURIComponent(indicatorValue)}/${section}`;
      break;
    case "hostname": // OTX memperlakukan hostname mirip dengan domain
      otxTypePath = `indicators/hostname/${encodeURIComponent(indicatorValue)}/${section}`;
      break;
    case "url":
      otxTypePath = `indicators/url/${encodeURIComponent(indicatorValue)}/${section}`;
      break;
    case "file": // Untuk hash (MD5, SHA1, SHA256)
      otxTypePath = `indicators/file/${encodeURIComponent(indicatorValue)}/${section}`;
      break;
    default:
      throw new OTXAPIError(`Unsupported OTX indicator type: ${indicatorType}`, 400);
  }

  try {
    const data = await makeOTXRequest(apiKey, otxTypePath);
    // Anda mungkin perlu memetakan respons data ke OTXIndicatorDetails
    // Ini adalah contoh sederhana; struktur respons OTX bisa kompleks
    const indicatorData: OTXIndicatorDetails = {
      indicator: data.indicator || indicatorValue,
      type: data.type || indicatorType,
      description: data.description,
      title: data.title,
      pulse_info: data.pulse_info, // Ini bisa berisi banyak info pulse
      tags: data.tags,
      // ... petakan field lain dari data OTX
    };
    return indicatorData;
  } catch (error) {
    if (error instanceof OTXAPIError) {
      // Jika error karena indikator tidak ditemukan (seringkali 404 dari OTX), anggap sebagai bukan error fatal
      if (error.statusCode === 404) {
        console.log(`OTX: Indicator ${indicatorValue} not found.`);
        return { detail: `Indicator ${indicatorValue} not found in OTX.` };
      }
    }
    console.error("Error fetching from OTX:", error);
    throw error; // Lempar ulang error yang lebih serius
  }
}

export async function checkIpOTX(apiKey: string, ip: string): Promise<OTXIndicatorDetails | OTXError> {
  return getIndicatorDetails(apiKey, "ip", ip, "general"); // Ambil section general dulu
}

export async function checkDomainOTX(apiKey: string, domain: string): Promise<OTXIndicatorDetails | OTXError> {
  return getIndicatorDetails(apiKey, "domain", domain, "general");
}

export async function checkUrlOTX(apiKey: string, url: string): Promise<OTXIndicatorDetails | OTXError> {
  // OTX mungkin memerlukan URL yang di-hash untuk pencarian, periksa dokumentasi API mereka
  // Untuk sementara, kita coba kirim URL langsung
  return getIndicatorDetails(apiKey, "url", url, "general");
}

export async function checkFileHashOTX(apiKey: string, hash: string): Promise<OTXIndicatorDetails | OTXError> {
  return getIndicatorDetails(apiKey, "file", hash, "general");
}

// Helper untuk mengecek apakah respons adalah error OTX
export function isOTXError(response: any): response is OTXError {
  return response && (typeof response.detail === 'string' || typeof response.error === 'string');
}
