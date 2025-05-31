// lib/siem-logger.ts
import { Client, errors as ElasticsearchErrors } from '@elastic/elasticsearch';
import type { NextRequest } from "next/server";

const ELASTICSEARCH_NODE = process.env.ELASTICSEARCH_NODE;
const ELASTICSEARCH_API_KEY = process.env.ELASTICSEARCH_API_KEY;
const ELASTICSEARCH_USERNAME = process.env.ELASTICSEARCH_USERNAME;
const ELASTICSEARCH_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;
const INDEX_PREFIX = process.env.ELASTICSEARCH_INDEX_PREFIX || 'pcap-scanner-logs-';
const APP_ENVIRONMENT = process.env.APP_ENV || process.env.NODE_ENV || 'development';

let client: Client | null = null;
let isElasticsearchHealthy = true; // Optimistically true, set to false on error

if (ELASTICSEARCH_NODE) {
  const clientOptions: any = { node: ELASTICSEARCH_NODE, requestTimeout: 5000 }; // Tambahkan requestTimeout

  if (ELASTICSEARCH_API_KEY) {
    clientOptions.auth = { apiKey: ELASTICSEARCH_API_KEY };
  } else if (ELASTICSEARCH_USERNAME && ELASTICSEARCH_PASSWORD) {
    clientOptions.auth = { username: ELASTICSEARCH_USERNAME, password: ELASTICSEARCH_PASSWORD };
  }

  // Konfigurasi TLS (sesuaikan dengan environment Elasticsearch Anda)
  if (ELASTICSEARCH_NODE.startsWith('https://')) {
      // Untuk Elastic Cloud atau HTTPS self-managed dengan CA valid, biasanya tidak perlu apa-apa.
      // Jika sertifikat self-signed, Anda mungkin perlu:
      // clientOptions.tls = { rejectUnauthorized: false }; // TIDAK DIREKOMENDASIKAN DI PRODUKSI
      // Atau sediakan CA: clientOptions.tls = { ca: 'path/to/ca.crt' };
  }


  client = new Client(clientOptions);

  // Initial health check and periodic check
  const checkElasticHealth = async () => {
    if (!client) {
        isElasticsearchHealthy = false;
        return;
    }
    try {
      await client.ping();
      if (!isElasticsearchHealthy) {
          console.log("[SIEM_LOGGER] Elasticsearch connection re-established.");
      }
      isElasticsearchHealthy = true;
    } catch (error) {
      if (isElasticsearchHealthy) { // Hanya log jika status berubah
          console.error("[SIEM_LOGGER] Elasticsearch ping failed. SIEM logging might be temporarily unavailable:", error instanceof Error ? error.message : error);
      }
      isElasticsearchHealthy = false;
      if (error instanceof ElasticsearchErrors.AuthenticationException) {
        console.error("[SIEM_LOGGER] Authentication error with Elasticsearch. Check credentials.");
      } else if (error instanceof ElasticsearchErrors.ConnectionError) {
        console.error("[SIEM_LOGGER] Connection error with Elasticsearch. Check ELASTICSEARCH_NODE and network.");
      }
    }
  };

  checkElasticHealth(); // Cek awal
  setInterval(checkElasticHealth, 60 * 1000); // Cek setiap menit

} else {
  console.warn("[SIEM_LOGGER] ELASTICSEARCH_NODE is not configured. SIEM logging will be disabled.");
  isElasticsearchHealthy = false;
}

function getCurrentDateIndexSuffix(): string {
  const date = new Date();
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  return `${year}.${month}.${day}`;
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
  severity?: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  details?: any;
  [key: string]: any;
}

export async function sendLogToSIEM(payload: Partial<LogPayload>): Promise<void> {
  if (!client || !isElasticsearchHealthy) {
    // Jangan log ke console jika memang ELASTICSEARCH_NODE tidak di-set
    if (ELASTICSEARCH_NODE && !isElasticsearchHealthy) {
        // console.warn("[SIEM_LOGGER] Client not ready or unhealthy. Log queued/discarded:", payload.message?.substring(0,100));
    }
    return;
  }

  const completePayload: LogPayload = {
    '@timestamp': new Date().toISOString(),
    service: 'pcap-ai-scanner',
    environment: APP_ENVIRONMENT,
    log_type: 'application_log',
    message: 'Log event',
    severity: 'INFO',
    ...payload,
  };

  const indexName = `${INDEX_PREFIX}${getCurrentDateIndexSuffix()}`;

  try {
    await client.index({
      index: indexName,
      document: completePayload,
    });
    // console.log(`[SIEM_LOGGER] Log sent to Elasticsearch index ${indexName}: ${completePayload.log_type} - ${completePayload.message.substring(0,100)}`);
  } catch (error) {
    console.error(`[SIEM_LOGGER] Error sending log to Elasticsearch index ${indexName}:`, error instanceof Error ? error.message : error);
    if (error instanceof ElasticsearchErrors.ConnectionError ||
        error instanceof ElasticsearchErrors.NoLivingConnectionsError ||
        (error instanceof ElasticsearchErrors.ResponseError && (error.statusCode === 502 || error.statusCode === 503 || error.statusCode === 504))
    ) {
        isElasticsearchHealthy = false; // Tandai tidak sehat jika ada error koneksi atau server
        console.warn("[SIEM_LOGGER] Elasticsearch connection/server error. SIEM logging paused.");
    } else if (error instanceof ElasticsearchErrors.AuthenticationException) {
        isElasticsearchHealthy = false;
        console.error("[SIEM_LOGGER] Elasticsearch authentication failed. SIEM logging paused.");
    }
  }
}

// Fungsi helper spesifik tetap berguna jika dipanggil dari HOF atau tempat lain
export function createAccessLogPayload(
    req: NextRequest,
    responseStatus: number,
    durationMs: number,
    userId?: string,
    userEmail?: string
): Partial<LogPayload> {
  return {
    log_type: 'access_log',
    message: `Access: ${req.method} ${req.nextUrl.pathname}`,
    http_method: req.method,
    request_path: req.nextUrl.pathname,
    source_ip: req.ip || req.headers.get('x-forwarded-for') || undefined,
    http_status_code: responseStatus,
    duration_ms: durationMs,
    user_id: userId,
    user_email: userEmail,
    details: {
        userAgent: req.headers.get('user-agent'),
        query_params: Object.fromEntries(req.nextUrl.searchParams)
    }
  };
}

export function createErrorLogPayload(
    error: Error,
    context?: { component?: string, [key: string]: any },
    req?: NextRequest,
    userId?: string,
    userEmail?: string
): Partial<LogPayload> {
  // Juga log ke console server untuk visibilitas langsung
  console.error(`[APP_ERROR_FOR_SIEM] ${context?.component || 'General Error'}:`, error.message, error.stack, "Context:", context, "User:", userEmail || userId);
  return {
    log_type: 'error_log',
    severity: 'ERROR',
    message: `Error in ${context?.component || 'application'}: ${error.message}`,
    error: {
      message: error.message,
      stack_trace: error.stack,
      type: error.name,
      code: (error as any).code,
    },
    user_id: userId,
    user_email: userEmail,
    request_path: req?.nextUrl.pathname,
    http_method: req?.method,
    source_ip: req?.ip || req?.headers.get('x-forwarded-for') || undefined,
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
    action: action,
    message: `Audit: User ${userEmail || userId || 'anonymous'} performed action: ${action} - ${status}`,
    user_id: userId,
    user_email: userEmail,
    details: {
        status,
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
    analysisId: string,
    fileName: string | null,
    status: 'upload_successful' | 'analysis_started' | 'analysis_completed_successfully' | 'analysis_failed' | 'analysis_deleted_by_user' | 'all_analyses_deleted_by_user',
    details?: any
): Partial<LogPayload> {
    let severity: LogPayload['severity'] = 'INFO';
    if (status === 'analysis_failed') severity = 'ERROR';
    else if (status.includes('deleted')) severity = 'WARNING';

    return {
        log_type: 'pcap_processing_log',
        action: `pcap_status:${status}`,
        message: `PCAP ${fileName || 'Unknown'} (ID: ${analysisId}) status: ${status}`,
        pcap_analysis_id: analysisId,
        pcap_file_name: fileName || undefined,
        severity,
        details: details
    };
}

export function createSecurityEventPayload(
    eventName: string,
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
