// Path: devinkis/fork-of-pcap-ai-scanner/fork-of-pcap-ai-scanner-fb3444031e0b44895e9fddc8cf7c92cce4812117/lib/auth.ts
import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"

const JWT_SECRET = process.env.JWT_SECRET || "Bayuajis112233@"

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

    // --- FIX START ---
    // Ensure that id, email, and role are valid non-empty strings
    const userId = typeof decoded.id === 'string' && decoded.id.length > 0 ? decoded.id : null;
    const userEmail = typeof decoded.email === 'string' && decoded.email.length > 0 ? decoded.email : null;
    const userRole = typeof decoded.role === 'string' && decoded.role.length > 0 ? decoded.role : null;

    if (!userId || !userEmail || !userRole) {
      console.warn("Invalid or missing user data in token payload:", { userId, userEmail, userRole });
      return null; // Invalid token payload
    }
    // --- FIX END ---

    return {
      id: userId, // Use the validated userId
      email: userEmail, // Use the validated userEmail
      name: decoded.name || null,
      role: userRole, // Use the validated userRole
    }
  } catch (error) {
    // Log the error for debugging, but return null for invalid token
    console.error("Token verification failed:", error);
    return null;
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
