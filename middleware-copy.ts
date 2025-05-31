// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { verifyJWT } from "@/lib/edge-auth"; // Pastikan path ini benar

export async function middleware(request: NextRequest) {
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

  const authToken = request.cookies.get("auth-token")?.value;

  if (!authToken) {
    const url = new URL("/login", request.url);
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname + request.nextUrl.search)); // Sertakan query params
    return NextResponse.redirect(url);
  }

  const JWT_SECRET = process.env.JWT_SECRET;
  if (!JWT_SECRET) {
    console.error("Middleware Error: JWT_SECRET is not defined in environment. User will be redirected to login.");
    const url = new URL("/login", request.url);
    url.searchParams.set("error", "server_config_error");
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname + request.nextUrl.search));
    // Hapus cookie yang mungkin salah jika ada
    const response = NextResponse.redirect(url);
    response.cookies.delete("auth-token");
    response.cookies.delete("auth-status");
    return response;
  }

  const user = await verifyJWT(authToken, JWT_SECRET); // Kirim JWT_SECRET ke verifyJWT

  if (!user) {
    const url = new URL("/login", request.url);
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname + request.nextUrl.search));
    url.searchParams.set("error", "session_expired"); // Atau "invalid_token"
    // Hapus cookie yang tidak valid
    const response = NextResponse.redirect(url);
    response.cookies.delete("auth-token");
    response.cookies.delete("auth-status");
    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
