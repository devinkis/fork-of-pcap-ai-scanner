import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { verifyToken } from "@/lib/auth"

export const runtime = 'nodejs';
export async function GET() {
  try {
    const cookieStore = cookies()
    const authToken = cookieStore.get("auth-token")?.value

    if (!authToken) {
      return NextResponse.json({ authenticated: false, reason: "no_token" })
    }

    const user = verifyToken(authToken)

    if (!user) {
      return NextResponse.json({ authenticated: false, reason: "invalid_token" })
    }

    return NextResponse.json({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    })
  } catch (error) {
    return NextResponse.json(
      {
        authenticated: false,
        reason: "error",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
