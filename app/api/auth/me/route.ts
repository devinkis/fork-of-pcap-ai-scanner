import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { verifyToken } from "@/lib/auth"

export const runtime = 'nodejs';
export async function GET() {
  try {
    const cookieStore = cookies()
    const authToken = cookieStore.get("auth-token")?.value

    console.log("ME endpoint - Auth token:", authToken ? `${authToken.substring(0, 10)}...` : "not found")

    if (!authToken) {
      console.log("ME endpoint - No auth token found")
      return NextResponse.json({ error: "Not authenticated", code: "no_token" }, { status: 401 })
    }

    // Verify the token
    let user
    try {
      user = verifyToken(authToken)
      console.log("ME endpoint - Token verified, user:", user?.email)
    } catch (error) {
      console.error("ME endpoint - Token verification error:", error)
      return NextResponse.json({ error: "Invalid token", code: "invalid_token" }, { status: 401 })
    }

    if (!user) {
      console.log("ME endpoint - Token verification returned no user")
      return NextResponse.json({ error: "Invalid token", code: "no_user_in_token" }, { status: 401 })
    }

    // Return the user information
    return NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    })
  } catch (error) {
    console.error("ME endpoint error:", error)
    return NextResponse.json(
      {
        error: "Internal server error",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
