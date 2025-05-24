import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { verifyJWT } from "@/lib/edge-auth"

export async function middleware(request: NextRequest) {
  // Get the pathname
  const path = request.nextUrl.pathname

  // Public paths that don't require authentication
  const publicPaths = ["/login", "/api/auth/login", "/api/health", "/api/admin/seed"]

  // Check if the path is public
  const isPublicPath = publicPaths.some((publicPath) => path === publicPath || path.startsWith(`${publicPath}/`))

  // Also allow all static assets
  const isStaticAsset =
    path.startsWith("/_next/") ||
    path.includes("/favicon.ico") ||
    path.includes(".svg") ||
    path.includes(".png") ||
    path.includes(".jpg") ||
    path.includes(".jpeg") ||
    path.includes(".gif")

  // If it's a public path or static asset, allow access
  if (isPublicPath || isStaticAsset) {
    return NextResponse.next()
  }

  // Special handling for API routes - only allow specific ones without auth
  const isApiPath = path.startsWith("/api/")
  if (isApiPath) {
    // List of API routes that don't require authentication
    const publicApiRoutes = ["/api/auth/login", "/api/health", "/api/admin/seed"]

    const isPublicApi = publicApiRoutes.some((route) => path.startsWith(route))
    if (isPublicApi) {
      return NextResponse.next()
    }
  }

  // Get auth token from cookies
  const authToken = request.cookies.get("auth-token")?.value

  // If no auth token, redirect to login
  if (!authToken) {
    const url = new URL("/login", request.url)
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname))
    return NextResponse.redirect(url)
  }

  // Verify the token
  const JWT_SECRET = process.env.JWT_SECRET || ""
  if (!JWT_SECRET) {
    console.error("JWT_SECRET is not defined")
    return NextResponse.redirect(new URL("/login?error=server_error", request.url))
  }

  const user = await verifyJWT(authToken, JWT_SECRET)

  // If token is invalid, redirect to login
  if (!user) {
    const url = new URL("/login", request.url)
    url.searchParams.set("callbackUrl", encodeURIComponent(request.nextUrl.pathname))
    url.searchParams.set("error", "session_expired")
    return NextResponse.redirect(url)
  }

  // User is authenticated, allow access
  return NextResponse.next()
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
}
