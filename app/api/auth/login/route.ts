import { type NextRequest, NextResponse } from "next/server"
import { verifyPassword, generateToken } from "@/lib/auth"
import { createPool } from "@vercel/postgres"

export const runtime = 'nodejs';
// Get the connection string from environment variables
const getConnectionString = () => {
  // Prioritize non-pooling connection for direct client connections
  if (process.env.POSTGRES_URL_NON_POOLING) {
    return process.env.POSTGRES_URL_NON_POOLING
  }
  return process.env.DATABASE_URL || process.env.POSTGRES_URL
}

// Create a connection pool that can be reused
const pool = createPool({
  connectionString: process.env.POSTGRES_URL || process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
})

// Simple in-memory rate limiting
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>()

// Clean up old rate limiting entries every hour
setInterval(
  () => {
    const now = Date.now()
    for (const [ip, data] of loginAttempts.entries()) {
      // Remove entries older than 1 hour
      if (now - data.lastAttempt > 60 * 60 * 1000) {
        loginAttempts.delete(ip)
      }
    }
  },
  60 * 60 * 1000,
)

export async function POST(request: NextRequest) {
  try {
    // Check if we have a connection string
    const connectionString = getConnectionString()
    if (!connectionString) {
      return NextResponse.json(
        { error: "Database configuration error. Please contact administrator." },
        { status: 500 },
      )
    }

    // Get client IP for rate limiting
    const ip = request.ip || request.headers.get("x-forwarded-for") || "unknown"

    // Check rate limiting
    const now = Date.now()
    const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: now }

    // Reset count if last attempt was more than 15 minutes ago
    if (now - attempts.lastAttempt > 15 * 60 * 1000) {
      attempts.count = 0
    }

    // Update attempt count and time
    attempts.count += 1
    attempts.lastAttempt = now
    loginAttempts.set(ip, attempts)

    // If too many attempts, block the request
    if (attempts.count > 5) {
      return NextResponse.json({ error: "Too many login attempts. Please try again later." }, { status: 429 })
    }

    const { email, password } = await request.json()

    if (!email || !password) {
      return NextResponse.json({ error: "Email and password are required" }, { status: 400 })
    }

    // Find user by email using pooled connection
    let user
    try {
      const client = await pool.connect()
      try {
        const result = await client.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [email.trim()])

        if (result.rows.length > 0) {
          const row = result.rows[0]
          user = {
            id: row.id,
            email: row.email,
            password: row.password,
            name: row.name,
            role: row.role,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
          }
        } else {
          // Use the same error message for security (don't reveal if email exists)
          return NextResponse.json({ error: "Invalid email or password" }, { status: 401 })
        }
      } finally {
        client.release()
      }
    } catch (dbError) {
      return NextResponse.json({ error: "Authentication failed" }, { status: 500 })
    }

    // Verify password
    let isValidPassword
    try {
      isValidPassword = await verifyPassword(password, user.password)
    } catch (pwError) {
      return NextResponse.json({ error: "Authentication failed" }, { status: 500 })
    }

    if (!isValidPassword) {
      return NextResponse.json({ error: "Invalid email or password" }, { status: 401 })
    }

    // On successful login, reset the attempt counter
    if (loginAttempts.has(ip)) {
      loginAttempts.set(ip, { count: 0, lastAttempt: now })
    }

    // Generate JWT token
    const token = generateToken({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    })

    // Create response
    const response = NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    })

    // Set secure cookie settings
    const isProduction = process.env.NODE_ENV === "production"

    // Set the auth token cookie with enhanced security
    response.cookies.set({
      name: "auth-token",
      value: token,
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 60 * 60 * 24, // 1 day
      path: "/",
    })

    // Set a non-httpOnly cookie for client-side auth detection
    // This doesn't contain sensitive data
    response.cookies.set({
      name: "auth-status",
      value: "authenticated",
      httpOnly: false,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 60 * 60 * 24, // 1 day
      path: "/",
    })

    return response
  } catch (error) {
    return NextResponse.json(
      {
        error: "Authentication failed",
      },
      { status: 500 },
    )
  }
}
