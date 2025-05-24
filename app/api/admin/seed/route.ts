import { NextResponse } from "next/server"
import { hash } from "bcryptjs"
import db from "@/lib/neon-db"
import type { NextRequest } from "next/server"

export async function POST(request: NextRequest) {
  try {
    // Get the seed key from the request
    let providedKey = ""

    try {
      const requestData = await request.json()
      providedKey = request.headers.get("x-seed-key") || requestData.seedKey || ""
    } catch (e) {
      providedKey = request.headers.get("x-seed-key") || ""
    }

    // Check if the seed key is valid
    if (!providedKey || providedKey !== process.env.SEED_KEY) {
      return NextResponse.json({ error: "Unauthorized: Invalid seed key" }, { status: 401 })
    }

    // Check if database connection is available
    const databaseUrl = process.env.DATABASE_URL || process.env.POSTGRES_URL
    if (!databaseUrl) {
      return NextResponse.json(
        {
          error: "Database connection string missing",
          details: "Neither DATABASE_URL nor POSTGRES_URL environment variable is set.",
          solution: "Add your database connection string to the environment variables.",
        },
        { status: 500 },
      )
    }

    console.log("🔄 Starting database seeding process...")

    // Test database connection first
    try {
      await db.testConnection()
    } catch (connectionError) {
      console.error("❌ Database connection test failed:", connectionError)
      return NextResponse.json(
        {
          error: "Failed to connect to database",
          details: connectionError instanceof Error ? connectionError.message : String(connectionError),
          solution: "Check your DATABASE_URL and ensure the database is accessible.",
        },
        { status: 500 },
      )
    }

    // Initialize database schema
    try {
      console.log("🔄 Initializing database schema...")
      await db.initializeDatabase()
      console.log("✅ Database schema initialized")
    } catch (dbError) {
      console.error("❌ Database initialization error:", dbError)
      return NextResponse.json(
        {
          error: "Failed to initialize database schema",
          details: dbError instanceof Error ? dbError.message : String(dbError),
          solution: "Ensure your database user has CREATE TABLE permissions.",
        },
        { status: 500 },
      )
    }

    // Create admin and user passwords
    console.log("🔄 Hashing passwords...")
    const adminPassword = await hash("admin123", 12)
    const userPassword = await hash("user123", 12)

    // Seed users
    try {
      console.log("🔄 Seeding users...")
      const seedResult = await db.seedUsers(adminPassword, userPassword)
      console.log("✅ Users seeded successfully")

      return NextResponse.json({
        success: true,
        message: "Database seeded successfully",
        users: seedResult.users,
        credentials: {
          admin: {
            email: "admin@pcapscanner.com",
            password: "admin123",
            role: "ADMIN",
          },
          user: {
            email: "user@pcapscanner.com",
            password: "user123",
            role: "USER",
          },
        },
        nextSteps: [
          "Database is now ready to use",
          "You can log in with the credentials above",
          "Visit /login to access the application",
        ],
      })
    } catch (seedError) {
      console.error("❌ User seeding error:", seedError)
      return NextResponse.json(
        {
          error: "Failed to seed users",
          details: seedError instanceof Error ? seedError.message : String(seedError),
          solution: "Check database permissions and try again.",
        },
        { status: 500 },
      )
    }
  } catch (error) {
    console.error("❌ Error seeding database:", error)
    return NextResponse.json(
      {
        error: "Failed to seed database",
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    )
  }
}
