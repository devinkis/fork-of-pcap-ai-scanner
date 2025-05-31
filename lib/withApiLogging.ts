// lib/withApiLogging.ts
import { type NextRequest, NextResponse } from 'next/server';
import {
  sendLogToSIEM,
  createAccessLogPayload,
  createErrorLogPayload,
  createAuditEventPayload,
  LogPayload
} from '@/lib/siem-logger';
import { getCurrentUser as getCurrentUserFromLib } from '@/lib/auth'; // Ganti nama agar tidak konflik

// Definisikan tipe User yang dikembalikan oleh getCurrentUserFromLib
interface AuthUser {
  id: string;
  email: string;
  role: string;
  name?: string | null;
}

type ApiHandler = (
  request: NextRequest,
  context: { params?: any }, // context.params mungkin ada untuk rute dinamis
  user?: AuthUser // User yang diautentikasi, opsional
) => Promise<NextResponse>;

interface UserContextForLog {
  id?: string;
  email?: string;
}

export function withApiLogging(handler: ApiHandler, auditActionInfo?: { action: string, targetResourceExtractor?: (request: NextRequest, context: { params?: any }, response?: NextResponse) => string | undefined }) {
  return async (request: NextRequest, context: { params?: any }) => {
    const startTime = Date.now();
    let response: NextResponse;
    let userContext: UserContextForLog = {};
    let errorOccurred: Error | null = null;
    let statusForLog: number = 500; // Default ke server error

    try {
      const user = await getCurrentUserFromLib(); // Panggil fungsi auth Anda
      if (user) {
        userContext = { id: user.id, email: user.email };
      }

      response = await handler(request, context, user || undefined); // Kirim user ke handler asli
      statusForLog = response.status;

      // Audit log jika action didefinisikan dan user ada
      if (auditActionInfo && user) {
        const auditStatus = response.ok ? 'success' : 'failure';
        let targetResourceId: string | undefined;
        if (auditActionInfo.targetResourceExtractor) {
            try {
                targetResourceId = auditActionInfo.targetResourceExtractor(request, context, response);
            } catch (e) {
                console.warn(`[withApiLogging] Error extracting target resource for audit: ${(e as Error).message}`);
            }
        }
        const auditDetails: any = {
            request_path: request.nextUrl.pathname,
            method: request.method,
            status_code: response.status, // Tambahkan status code ke detail audit
        };
        if (context.params) {
            auditDetails.params = context.params;
        }
        if (targetResourceId) {
            auditDetails.target_resource_id = targetResourceId;
        }
        // Logika untuk mengambil detail dari body respons (jika JSON dan tidak terlalu besar)
        // if (response.headers.get('content-type')?.includes('application/json') && response.ok) {
        //   try {
        //     const responseClone = response.clone();
        //     const responseBody = await responseClone.json();
        //     // Ambil hanya field tertentu atau batasi ukuran
        //     auditDetails.response_summary = { /* field penting dari responseBody */ };
        //   } catch (e) { /* abaikan jika parsing gagal */ }
        // }

        sendLogToSIEM(createAuditEventPayload(auditActionInfo.action, user.id, user.email, auditStatus, auditDetails));
      }

    } catch (err) {
      errorOccurred = err as Error;
      // Coba dapatkan user lagi jika error terjadi sebelum user diambil di blok try utama
      if (!userContext.id) {
        try {
            const user = await getCurrentUserFromLib();
            if (user) userContext = { id: user.id, email: user.email };
        } catch { /* abaikan jika user tidak bisa didapatkan saat error */ }
      }

      console.error(`[withApiLogging] Error in handler for ${request.method} ${request.nextUrl.pathname}:`, err);
      if (err instanceof NextResponse) {
        response = err;
        statusForLog = err.status;
      } else {
        response = NextResponse.json({ error: 'Internal Server Error', details: (err as Error).message }, { status: 500 });
        statusForLog = 500;
      }
    } finally {
      const durationMs = Date.now() - startTime;
      // Pastikan log akses dikirim bahkan jika response tidak terdefinisi karena error awal
      sendLogToSIEM(createAccessLogPayload(request, statusForLog, durationMs, userContext.id, userContext.email));

      if (errorOccurred && !(errorOccurred instanceof NextResponse)) {
        sendLogToSIEM(
          createErrorLogPayload(
            errorOccurred,
            { component: `API:${request.nextUrl.pathname}`, method: request.method, params: context.params },
            request,
            userContext.id,
            userContext.email
          )
        );
      }
    }
    return response;
  };
}
