// lib/siem-logger.ts
import { Client, errors as ElasticsearchErrors } from '@elastic/elasticsearch';
import type { NextRequest } from "next/server"; // Hanya untuk type hint jika diperlukan

const ELASTICSEARCH_NODE = process.env.ELASTICSEARCH_NODE;
const ELASTICSEARCH_API_KEY = process.env.ELASTICSEARCH_API_KEY;
const ELASTICSEARCH_USERNAME = process.env.ELASTICSEARCH_USERNAME;
const ELASTICSEARCH_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;
const INDEX_PREFIX = process.env.ELASTICSEARCH_INDEX_PREFIX || 'pcap-scanner-logs-';
const APP_ENVIRONMENT = process.env.APP_ENV || process.env.NODE_ENV || 'development';

let client: Client | null = null;
let isElasticsearchHealthy = false; // Mulai dengan false sampai koneksi terverifikasi

if (ELASTICSEARCH_NODE) {
  const clientOptions: any = {
    node: ELASTICSEARCH_NODE,
    requestTimeout: 5000, // Timeout untuk request ke Elasticsearch
    sniffOnStart: false, // Umumnya false untuk Elastic Cloud
    sniffOnConnectionFault: false, // Umumnya false untuk Elastic Cloud
  };

  if (ELASTICSEARCH_API_KEY) {
    clientOptions.auth = { apiKey: ELASTICSEARCH_API_KEY };
  } else if (ELASTICSEARCH_USERNAME && ELASTICSEARCH_PASSWORD) {
    clientOptions.auth = { username: ELASTICSEARCH_USERNAME, password: ELASTICSEARCH_PASSWORD };
  }

  // Konfigurasi TLS:
  // Jika ELASTICSEARCH_NODE dimulai dengan https://, library akan menggunakan HTTPS.
  // Untuk Elastic Cloud, biasanya tidak perlu konfigurasi tls tambahan di client.
  // Untuk self-managed dengan sertifikat CA kustom:
  // clientOptions.tls = { ca: Buffer.from('---BEGIN CERTIFICATE---\nYOUR_CA_CERT\n---END CERTIFICATE---'), rejectUnauthorized: true };
  // Untuk self-managed dengan sertifikat self-signed (TIDAK DIREKOMENDASIKAN untuk produksi):
  if (process.env.NODE_ENV !== 'production' && ELASTICSEARCH_NODE.startsWith('https://')) {
    // clientOptions.tls = { rejectUnauthorized: false }; // Hanya untuk dev jika sertifikat self-signed
  }

  try {
    client = new Client(clientOptions);

    const checkElasticHealth = async () => {
      if (!client) {
        isElasticsearchHealthy = false;
        return;
      }
      try {
        await client.ping();
        if (!isElasticsearchHealthy) { // Log hanya jika status berubah menjadi sehat
          console.log("[SIEM_LOGGER] Elasticsearch connection established and healthy.");
        }
        isElasticsearchHealthy = true;
      } catch (error) {
        if (isElasticsearchHealthy) { // Log hanya jika status berubah menjadi tidak sehat
          console.error("[SIEM_LOGGER] Elasticsearch ping failed. SIEM logging might be temporarily unavailable:", error instanceof Error ? error.message : String(error));
        }
        isElasticsearchHealthy = false;
        // Tambahan detail error jika relevan
        if (error instanceof ElasticsearchErrors.AuthenticationException) {
          console.error("[SIEM_LOGGER] Authentication error with Elasticsearch. Check credentials.");
        } else if (error instanceof ElasticsearchErrors.ConnectionError || error instanceof ElasticsearchErrors.NoLivingConnectionsError) {
          console.error("[SIEM_LOGGER] Connection error with Elasticsearch. Check ELASTICSEARCH_NODE, network, and service status.");
        }
      }
    };

    checkElasticHealth(); // Cek awal saat inisialisasi
    setInterval(checkElasticHealth, 60 * 1000); // Cek kesehatan setiap 60 detik

  } catch (initError) {
    console.error("[SIEM_LOGGER] Failed to initialize Elasticsearch client:", initError instanceof Error ? initError.message : String(initError));
    client = null;
    isElasticsearchHealthy = false;
  }

} else {
  console.warn("[SIEM_LOGGER] ELASTICSEARCH_NODE environment variable is not configured. SIEM logging will be disabled.");
  isElasticsearchHealthy = false;
}

function getCurrentDateIndexSuffix(): string {
  const date = new Date();
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  // Indeks Harian (direkomendasikan):
  const day = date.getDate().toString().padStart(2, '0');
  return `${year}.${month}.${day}`;
  // Alternatif: Indeks Bulanan
  // return `${year}.${month}`;
}

export interface LogPayload {
  '@timestamp': string;
  service: string;
  environment: string;
  log_type: 'application_log' | 'access_log' | 'error_log' | 'audit_log' | 'traffic_summary_log' | 'usage_log' | 'pcap_processing_log' | 'security_event';
  message: string;
  user_id?: string;
  user_email?: string;
  source_ip?: string;
  request_path?: string;
  http_method?: string;
  http_status_code?: number;
  duration_ms?: number;
  error?: {
    message: string;
    stack_trace?: string;
    type?: string;
    code?: string;
  };
  action?: string;
  target_resource_id?: string;
  pcap_analysis_id?: string;
  pcap_file_name?: string;
  traffic_summary?: any;
  severity?: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL'; // Severity level
  details?: any;
  [key: string]: any; // Untuk field tambahan
}

export async function sendLogToSIEM(payload: Partial<LogPayload>): Promise<void> {
  if (!client || !isElasticsearchHealthy) {
    if (ELASTICSEARCH_NODE && !isElasticsearchHealthy) { // Hanya log jika node dikonfigurasi tapi tidak sehat
        // Untuk menghindari flooding log, mungkin hanya log ini sesekali atau dengan sampling
        // console.warn(`[SIEM_LOGGER] Client not ready or unhealthy. Log for "${payload.message?.substring(0,50)}..." being discarded.`);
    } else if (!ELASTICSEARCH_NODE) {
        // console.warn("[SIEM_LOGGER] ELASTICSEARCH_NODE not configured. Log discarded.");
    }
    // Pertimbangkan untuk menulis ke console sebagai fallback jika Elastic tidak tersedia:
    // console.log(`[SIEM_FALLBACK_LOG]: ${JSON.stringify({ ...defaultFields, ...payload })}`);
    return;
  }

  const completePayload: LogPayload = {
    '@timestamp': new Date().toISOString(),
    service: 'pcap-ai-scanner',
    environment: APP_ENVIRONMENT,
    log_type: 'application_log', // default
    message: 'Log event',       // default
    severity: 'INFO',           // default
    ...payload,
  };

  const indexName = `${INDEX_PREFIX}${getCurrentDateIndexSuffix()}`;

  try {
    // Menggunakan endpoint _bulk untuk efisiensi, bahkan untuk satu log.
    // Ini juga memungkinkan batching di masa depan jika diperlukan.
    const operations = [
        { index: { _index: indexName } },
        completePayload
    ];
    const bulkResponse = await client.bulk({ refresh: false, operations });

    if (bulkResponse.errors) {
      const erroredDocuments = [];
      bulkResponse.items.forEach((action: any, i: number) => {
        const operation = Object.keys(action)[0];
        if (action[operation].error) {
          erroredDocuments.push({
            status: action[operation].status,
            error: action[operation].error,
            operation: operations[i * 2], // Header
            document: operations[i * 2 + 1] // Dokumen
          });
        }
      });
      console.error('[SIEM_LOGGER] Errors in Elasticsearch bulk response:', JSON.stringify(erroredDocuments, null, 2));
    } else {
      // console.log(`[SIEM_LOGGER] Log sent to Elasticsearch index ${indexName}: ${completePayload.log_type} - ${completePayload.message?.substring(0,100)}`);
    }
  } catch (error) {
    console.error(`[SIEM_LOGGER] Exception sending log to Elasticsearch index ${indexName}:`, error instanceof Error ? error.message : String(error));
    if (error instanceof ElasticsearchErrors.ConnectionError ||
        error instanceof ElasticsearchErrors.NoLivingConnectionsError ||
        (error instanceof ElasticsearchErrors.ResponseError && (error.statusCode === 502 || error.statusCode === 503 || error.statusCode === 504))
    ) {
        isElasticsearchHealthy = false;
        console.warn("[SIEM_LOGGER] Elasticsearch connection/server error during send. SIEM logging paused.");
    } else if (error instanceof ElasticsearchErrors.AuthenticationException) {
        isElasticsearchHealthy = false;
        console.error("[SIEM_LOGGER] Elasticsearch authentication failed during send. SIEM logging paused.");
    }
    // Pertimbangkan retry sederhana dengan backoff atau dead-letter queue
  }
}

// --- Helper functions untuk membuat payload log ---
// Ini tidak mengirim log, hanya membuat objek payload. Pengiriman dilakukan oleh HOF atau pemanggil langsung.

export function createAccessLogPayload(
    req: NextRequest, // Sekarang NextRequest adalah opsional
    responseStatus: number,
    durationMs: number,
    userId?: string,
    userEmail?: string,
    requestPathOverride?: string // Untuk kasus di mana req.nextUrl.pathname mungkin belum final
): Partial<LogPayload> {
  const path = requestPathOverride || req?.nextUrl?.pathname || "unknown_path";
  const method = req?.method || "UNKNOWN_METHOD";
  return {
    log_type: 'access_log',
    message: `Access: ${method} ${path}`,
    http_method: method,
    request_path: path,
    source_ip: req?.ip || req?.headers?.get('x-forwarded-for') || req?.headers?.get('x-real-ip') || undefined,
    http_status_code: responseStatus,
    duration_ms: durationMs,
    user_id: userId,
    user_email: userEmail,
    details: {
        userAgent: req?.headers?.get('user-agent'),
        query_params: req?.nextUrl?.searchParams ? Object.fromEntries(req.nextUrl.searchParams) : undefined,
        referer: req?.headers?.get('referer')
    }
  };
}

export function createErrorLogPayload(
    error: Error,
    context?: { component?: string, [key: string]: any },
    req?: NextRequest, // Sekarang NextRequest adalah opsional
    userId?: string,
    userEmail?: string
): Partial<LogPayload> {
  // Juga log ke console server untuk visibilitas langsung, ini penting untuk debugging Vercel
  console.error(`[APP_ERROR_FOR_SIEM_AND_CONSOLE] Component: ${context?.component || 'General Error'}. Message: ${error.message}. Stack: ${error.stack}. Context: ${JSON.stringify(context)}. User: ${userEmail || userId || 'N/A'}`);

  return {
    log_type: 'error_log',
    severity: 'ERROR',
    message: `Error in ${context?.component || 'application'}: ${error.message}`,
    error: {
      message: error.message,
      stack_trace: error.stack,
      type: error.name, // mis. 'TypeError', 'SyntaxError'
      code: (error as any).code, // Jika ada kode error spesifik aplikasi
    },
    user_id: userId,
    user_email: userEmail,
    request_path: req?.nextUrl?.pathname,
    http_method: req?.method,
    source_ip: req?.ip || req?.headers?.get('x-forwarded-for') || req?.headers?.get('x-real-ip') || undefined,
    details: context,
  };
}

export function createAuditEventPayload(
    action: string,
    userId: string | undefined,
    userEmail: string | undefined,
    status: 'success' | 'failure',
    details?: any
): Partial<LogPayload> {
  return {
    log_type: 'audit_log',
    action: action, // e.g., 'user_login', 'file_upload', 'admin_create_user'
    message: `Audit: User ${userEmail || userId || 'anonymous'} action: ${action} - ${status}`,
    user_id: userId,
    user_email: userEmail,
    details: {
        status, // 'success' atau 'failure'
        ...details,
    },
  };
}

export function createUsageEventPayload(
    feature: string,
    userId: string | undefined,
    userEmail: string | undefined,
    details?: any
): Partial<LogPayload> {
    return {
      log_type: 'usage_log',
      action: `feature_used:${feature}`,
      message: `Usage: User ${userEmail || userId || 'anonymous'} used feature: ${feature}`,
      user_id: userId,
      user_email: userEmail,
      details: details,
    };
}

export function createPcapProcessingEventPayload(
    analysisId: string | undefined,
    fileName: string | null | undefined,
    status: 'upload_initiated' | 'upload_successful' | 'upload_failed' | 'upload_blob_failed' | 'analysis_queued' | 'analysis_started' | 'analysis_completed_successfully' | 'analysis_failed' | 'analysis_deleted_by_user' | 'all_analyses_deleted_by_user',
    details?: any
): Partial<LogPayload> {
    let severity: LogPayload['severity'] = 'INFO';
    if (status.includes('failed')) severity = 'ERROR';
    else if (status.includes('deleted')) severity = 'WARNING';

    return {
        log_type: 'pcap_processing_log',
        action: `pcap_status:${status}`,
        message: `PCAP ${fileName || 'Unknown Filename'} (ID: ${analysisId || 'Unknown ID'}) status: ${status}`,
        pcap_analysis_id: analysisId,
        pcap_file_name: fileName || undefined,
        severity,
        details: details
    };
}

export function createSecurityEventPayload(
    eventName: string, // e.g., 'high_threat_pcap_analysis', 'failed_login_ratelimit'
    severity: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL',
    description: string,
    details?: any
): Partial<LogPayload> {
    return {
        log_type: 'security_event',
        message: `Security Event: ${eventName} - ${description}`,
        action: `security_event:${eventName}`,
        severity,
        details,
    };
}
