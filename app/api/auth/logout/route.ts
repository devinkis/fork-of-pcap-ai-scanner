import { NextResponse } from "next/server"
import { cookies } from "next/headers"

export async function POST() {
  try {
    const cookieStore = cookies()

    // Clear all authentication cookies
    cookieStore.delete({
      name: "auth-token",
      path: "/",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
    })

    cookieStore.delete({
      name: "auth-status",
      path: "/",
      secure: process.env.NODE_ENV === "production",
      httpOnly: false,
      sameSite: "lax",
    })

    // Clear any legacy cookies
    cookieStore.delete("session_token")
    cookieStore.delete("user_id")

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Logout error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
