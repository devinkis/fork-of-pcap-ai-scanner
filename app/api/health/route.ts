import { NextResponse } from "next/server"
import { createClient } from "@vercel/postgres"

// Get the connection string from environment variables
const getConnectionString = () => {
  // For direct client connections in API routes, prioritize non-pooling
  if (process.env.POSTGRES_URL_NON_POOLING) {
    return process.env.POSTGRES_URL_NON_POOLING
  }
  return process.env.DATABASE_URL || process.env.POSTGRES_URL
}

export async function GET() {
  try {
    // Check environment variables
    const databaseUrlSet = !!process.env.DATABASE_URL
    const postgresUrlSet = !!process.env.POSTGRES_URL
    const postgresUrlNonPoolingSet = !!process.env.POSTGRES_URL_NON_POOLING
    const jwtSecretSet = !!process.env.JWT_SECRET
    const seedKeySet = !!process.env.SEED_KEY
    const blobTokenSet = !!process.env.BLOB_READ_WRITE_TOKEN
    const virusTotalApiKeySet = !!process.env.VIRUSTOTAL_API_KEY
    const malwareBazaarApiKeySet = !!process.env.MALWAREBAZAAR_API_KEY

    console.log("🔍 Health check - Environment variables:")
    console.log(`DATABASE_URL: ${databaseUrlSet ? "✅ Set" : "❌ Not set"}`)
    console.log(`POSTGRES_URL: ${postgresUrlSet ? "✅ Set" : "❌ Not set"}`)
    console.log(`POSTGRES_URL_NON_POOLING: ${postgresUrlNonPoolingSet ? "✅ Set" : "❌ Not set"}`)
    console.log(`JWT_SECRET: ${jwtSecretSet ? "✅ Set" : "❌ Not set"}`)

    const connectionString = getConnectionString()
    if (!connectionString) {
      return NextResponse.json(
        {
          status: "error",
          database: "not configured",
          error: "No database connection string found",
          timestamp: new Date().toISOString(),
          config: {
            databaseUrlSet,
            postgresUrlSet,
            postgresUrlNonPoolingSet,
            jwtSecretSet,
            seedKeySet,
            blobTokenSet,
            virusTotalApiKeySet,
            malwareBazaarApiKeySet,
          },
          suggestions: [
            "1. Add DATABASE_URL, POSTGRES_URL, or POSTGRES_URL_NON_POOLING to your environment variables",
            "2. If using Vercel, add the environment variable in your project settings",
            "3. If using Neon, copy the connection string from your Neon dashboard",
            "4. Make sure the connection string includes the database name and credentials",
          ],
        },
        { status: 500 },
      )
    }

    // Test database connection
    try {
      console.log("🔄 Testing database connection...")
      const client = createClient({
        connectionString,
        ssl: { rejectUnauthorized: false },
      })
      await client.connect()

      try {
        const testResult = await client.query("SELECT 1 as test, NOW() as current_time")
        console.log("✅ Database connection successful")

        // Test if tables exist
        const tablesResult = await client.query(`
          SELECT table_name 
          FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name IN ('users', 'pcap_files')
        `)

        const existingTables = tablesResult.rows.map((row) => row.table_name)
        const hasUsersTable = existingTables.includes("users")
        const hasPcapFilesTable = existingTables.includes("pcap_files")

        let userCount = 0
        if (hasUsersTable) {
          try {
            const userCountResult = await client.query("SELECT COUNT(*) as count FROM users")
            userCount = Number(userCountResult.rows[0]?.count || 0)
          } catch (error) {
            console.warn("⚠️ Could not count users:", error)
          }
        }

        return NextResponse.json({
          status: "ok",
          database: "connected",
          timestamp: new Date().toISOString(),
          connection: {
            successful: true,
            serverTime: testResult.rows[0]?.current_time,
          },
          schema: {
            usersTable: hasUsersTable,
            pcapFilesTable: hasPcapFilesTable,
            userCount,
            needsSeeding: userCount === 0,
          },
          config: {
            databaseUrlSet,
            postgresUrlSet,
            postgresUrlNonPoolingSet,
            jwtSecretSet,
            seedKeySet,
            blobTokenSet,
            virusTotalApiKeySet,
            malwareBazaarApiKeySet,
          },
          nextSteps:
            userCount === 0
              ? [
                  "Database is connected but empty",
                  "Visit /admin/seed to initialize with default users",
                  "Or use the API endpoint /api/admin/seed with the SEED_KEY",
                ]
              : ["Database is ready to use", "You can log in with the seeded user accounts"],
        })
      } finally {
        await client.end()
      }
    } catch (dbError) {
      console.error("❌ Database connection failed:", dbError)

      return NextResponse.json(
        {
          status: "error",
          database: "connection failed",
          error: dbError instanceof Error ? dbError.message : "Unknown database error",
          timestamp: new Date().toISOString(),
          config: {
            databaseUrlSet,
            postgresUrlSet,
            postgresUrlNonPoolingSet,
            jwtSecretSet,
            seedKeySet,
            blobTokenSet,
            virusTotalApiKeySet,
            malwareBazaarApiKeySet,
          },
          troubleshooting: [
            "1. Verify your DATABASE_URL is correct",
            "2. Check if your database server is running",
            "3. Ensure your IP is whitelisted (for cloud databases)",
            "4. Verify database credentials are correct",
            "5. Check if the database name exists",
          ],
        },
        { status: 500 },
      )
    }
  } catch (error) {
    console.error("❌ Health check failed:", error)

    return NextResponse.json(
      {
        status: "error",
        database: "check failed",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
      },
      { status: 500 },
    )
  }
}
