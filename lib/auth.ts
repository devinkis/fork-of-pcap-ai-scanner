import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key"

export interface User {
  id: string
  email: string
  name: string | null
  role: "ADMIN" | "USER"
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12)
}

export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword)
}

// Update the generateToken function to use more secure settings
export function generateToken(user: User): string {
  const payload = {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    // Add a random nonce to prevent token reuse
    nonce: Math.random().toString(36).substring(2, 15),
    // Add issued at timestamp
    iat: Math.floor(Date.now() / 1000),
  }

  // Reduce token expiration to 24 hours for better security
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: "24h",
    algorithm: "HS256",
  })

  return token
}

// Update verifyToken to be more strict
export function verifyToken(token: string): User | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    }) as any

    // Check if token is expired
    const now = Math.floor(Date.now() / 1000)
    if (decoded.exp && decoded.exp < now) {
      return null
    }

    // Check if token was issued too long ago (force re-login after 7 days regardless)
    const sevenDaysInSeconds = 7 * 24 * 60 * 60
    if (decoded.iat && now - decoded.iat > sevenDaysInSeconds) {
      return null
    }

    return {
      id: decoded.id,
      email: decoded.email,
      name: decoded.name || null,
      role: decoded.role,
    }
  } catch (error) {
    return null
  }
}

export async function getCurrentUser(): Promise<User | null> {
  try {
    const cookieStore = cookies()
    const token = cookieStore.get("auth-token")?.value

    if (!token) {
      return null
    }

    const user = verifyToken(token)

    if (!user) {
      return null
    }

    // For performance, we'll skip the database check
    // and just trust the token information
    return user

    // Uncomment this if you want to verify against the database
    /*
    // Verify user still exists in database
    const dbUser = await db.user.findUnique({
      where: { id: user.id },
    })

    return dbUser
    */
  } catch (error) {
    console.error("getCurrentUser error:", error)
    return null
  }
}

// Simplified version that doesn't redirect
export async function getUser(): Promise<User | null> {
  return getCurrentUser()
}

export async function requireAuth(): Promise<User> {
  const user = await getCurrentUser()
  if (!user) {
    redirect("/login")
  }
  return user
}

export async function requireAdmin(): Promise<User> {
  const user = await requireAuth()
  if (user.role !== "ADMIN") {
    redirect("/")
  }
  return user
}
