import { NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import db from "@/lib/neon-db"
import { sql } from "@vercel/postgres"

export const runtime = 'nodejs';
export async function POST() {
  try {
    // Only allow this in development or with proper authorization
    if (process.env.NODE_ENV === "production") {
      const seedKey = process.env.SEED_KEY
      if (!seedKey) {
        return NextResponse.json({ error: "Not authorized" }, { status: 401 })
      }
    }

    // Hash passwords
    const adminPassword = await bcrypt.hash("admin123", 12)
    const userPassword = await bcrypt.hash("user123", 12)

    // Update admin password
    await sql`
      UPDATE users 
      SET password = ${adminPassword}
      WHERE email = ${"admin@pcapscanner.com"}
    `

    // Update user password
    await sql`
      UPDATE users 
      SET password = ${userPassword}
      WHERE email = ${"user@pcapscanner.com"}
    `

    // Get updated users
    const users = await db.user.findMany({
      select: {
        id: true,
        email: true,
        role: true,
      },
    })

    return NextResponse.json({
      success: true,
      message: "Passwords reset successfully",
      users,
    })
  } catch (error) {
    console.error("Error resetting passwords:", error)
    return NextResponse.json(
      {
        error: "Failed to reset passwords",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
