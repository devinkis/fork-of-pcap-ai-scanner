// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { verifyJWT } from "@/lib/edge-auth";
import { sendLogToSIEM, createAccessLogPayload } from "@/lib/siem-logger"; // Hanya sendLogToSIEM dan createAccessLogPayload
import { User } from "@/lib/auth"; // Asumsikan User diekspor dari lib/auth

export async function middleware(request: NextRequest) {
  const startTime = Date.now();
  let userFromToken: User | null = null;

  const path = request.nextUrl.pathname;
  const publicPaths = ["/login", "/api/auth/login", "/api/health", "/api/admin/seed"];
  const isPublicPath = publicPaths.some((publicPath) => path === publicPath || path.startsWith(`${publicPath}/`));

  const isStaticAsset =
    path.startsWith("/_next/") ||
    path.includes("/favicon.ico") ||
    path.includes(".svg") ||
    path.includes(".png") ||
    path.includes(".jpg") ||
    path.includes(".jpeg") ||
    path.includes(".gif");

  const authToken = request.cookies.get("auth-token")?.value;
  if (authToken) {
    const JWT_SECRET = process.env.JWT_SECRET;
    if (JWT_SECRET) {
      userFromToken = await verifyJWT(authToken, JWT_SECRET);
    }
  }

  // Log akses di awal, status akan diupdate oleh HOF jika rute itu menggunakannya
  // Untuk rute publik atau yang tidak di-wrap HOF, ini akan menjadi log utama
  if (!isStaticAsset) { // Hindari logging aset statis yang berlebihan
    // Kirim log akses awal. Status code belum diketahui. HOF akan mengirim log akses yang lebih lengkap.
    // Jika rute ini tidak di-wrap HOF, log ini adalah satu-satunya.
    // Pertimbangkan untuk hanya log di HOF jika memungkinkan, atau log ini dengan status placeholder.
    // sendLogToSIEM(createAccessLogPayload(request, 0 /* placeholder status */, 0 /* placeholder duration */, userFromToken?.id, userFromToken?.email));
  }


  if (isPublicPath || isStaticAsset) {
    return NextResponse.next();
  }

  const isApiPath = path.startsWith("/api/");
  if (isApiPath) {
    const publicApiRoutes = ["/api/auth/login", "/api/health", "/api/admin/seed"];
    const isPublicApi = publicApiRoutes.some((route) => path.startsWith(route));
    if (isPublicApi) {
      return NextResponse.next();
    }
  }

  if (!authToken) {
    const url = new URL("/login", request.url);
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname + request.nextUrl.search));
    const redirectResponse = NextResponse.redirect(url);
    // Log akses untuk redirect ini
    if (!isStaticAsset) {
        const durationMs = Date.now() - startTime;
        sendLogToSIEM(createAccessLogPayload(request, redirectResponse.status, durationMs, userFromToken?.id, userFromToken?.email));
    }
    return redirectResponse;
  }

  const JWT_SECRET = process.env.JWT_SECRET;
  if (!JWT_SECRET) {
    console.error("Middleware Error: JWT_SECRET is not defined. User will be redirected to login.");
    const url = new URL("/login", request.url);
    url.searchParams.set("error", "server_config_error");
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname + request.nextUrl.search));
    const errorResponse = NextResponse.redirect(url);
    errorResponse.cookies.delete("auth-token");
    errorResponse.cookies.delete("auth-status");
    if (!isStaticAsset) {
        const durationMs = Date.now() - startTime;
        sendLogToSIEM(createAccessLogPayload(request, errorResponse.status, durationMs, userFromToken?.id, userFromToken?.email));
    }
    return errorResponse;
  }

  if (!userFromToken) { // Jika token ada tapi tidak valid
    const url = new URL("/login", request.url);
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname + request.nextUrl.search));
    url.searchParams.set("error", "session_expired");
    const invalidTokenResponse = NextResponse.redirect(url);
    invalidTokenResponse.cookies.delete("auth-token");
    invalidTokenResponse.cookies.delete("auth-status");
    if (!isStaticAsset) {
        const durationMs = Date.now() - startTime;
        sendLogToSIEM(createAccessLogPayload(request, invalidTokenResponse.status, durationMs));
    }
    return invalidTokenResponse;
  }

  // Jika user terautentikasi dan bukan path publik
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
