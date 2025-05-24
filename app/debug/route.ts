import { NextResponse } from "next/server"
import { getCurrentUser } from "@/lib/auth"
import db from "@/lib/neon-db"

export async function GET() {
  try {
    // Get current user
    const user = await getCurrentUser()

    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    // Only allow admins to access this endpoint
    if (user.role !== "ADMIN") {
      return NextResponse.json({ error: "Admin access required" }, { status: 403 })
    }

    // Test database connection
    console.log("Testing database connection...")
    const connectionTest = await db.testConnection()

    // Get database environment variables (redacted for security)
    const dbEnv = {
      DATABASE_URL: process.env.DATABASE_URL ? "[REDACTED]" : undefined,
      POSTGRES_URL: process.env.POSTGRES_URL ? "[REDACTED]" : undefined,
      POSTGRES_URL_NON_POOLING: process.env.POSTGRES_URL_NON_POOLING ? "[REDACTED]" : undefined,
    }

    // Get all PCAP files for the current user
    console.log("Fetching PCAP files...")
    const pcapFiles = []

    try {
      // Query the database directly
      const client = await db.createDbClient()
      await client.connect()

      try {
        const result = await client.query("SELECT * FROM pcap_files WHERE user_id = $1", [user.id])
        for (const row of result.rows) {
          pcapFiles.push({
            id: row.id,
            fileName: row.file_name,
            originalName: row.original_name,
            size: row.size,
            analysisId: row.analysis_id,
            userId: row.user_id,
            createdAt: row.created_at,
          })
        }
      } finally {
        await client.end()
      }
    } catch (error) {
      console.error("Error fetching PCAP files:", error)
    }

    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      database: {
        connectionTest,
        environment: dbEnv,
      },
      pcapFiles,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Debug endpoint error:", error)
    return NextResponse.json(
      {
        error: "Failed to get debug information",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
