// lib/auth.ts
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import bcrypt from "bcryptjs"; // Pastikan bcryptjs terinstal dan diimpor
import jwt from "jsonwebtoken";

// Ambil JWT_SECRET dari environment variable, dengan fallback jika diperlukan (tidak direkomendasikan untuk produksi)
const JWT_SECRET = process.env.JWT_SECRET || "YOUR_FALLBACK_SECRET_CHANGE_THIS_IN_ENV";
if (process.env.NODE_ENV === "production" && JWT_SECRET === "YOUR_FALLBACK_SECRET_CHANGE_THIS_IN_ENV") {
  console.warn("CRITICAL SECURITY WARNING: JWT_SECRET is using a fallback value in production. Please set a strong, unique secret in your environment variables.");
}


export interface User {
  id: string;
  email: string;
  name: string | null;
  role: "ADMIN" | "USER";
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

export function generateToken(user: User): string {
  const payload = {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    nonce: Math.random().toString(36).substring(2, 15),
    iat: Math.floor(Date.now() / 1000),
  };

  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined. Cannot generate token.");
  }

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: "24h",
    algorithm: "HS256",
  });

  return token;
}

export function verifyToken(token: string): User | null {
  try {
    if (!JWT_SECRET) {
      console.error("verifyToken Error: JWT_SECRET is not defined. Cannot verify token.");
      return null;
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    }) as any;

    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp && decoded.exp < now) {
      console.warn("verifyToken: Token has expired (exp check).");
      return null;
    }

    const sevenDaysInSeconds = 7 * 24 * 60 * 60;
    if (decoded.iat && now - decoded.iat > sevenDaysInSeconds) {
      console.warn("verifyToken: Token is older than 7 days (iat check).");
      return null;
    }

    const userId = typeof decoded.id === 'string' && decoded.id.length > 0 ? decoded.id : null;
    const userEmail = typeof decoded.email === 'string' && decoded.email.length > 0 ? decoded.email : null;
    const userRole = typeof decoded.role === 'string' && decoded.role.length > 0 ? decoded.role : null;

    if (!userId || !userEmail || !userRole) {
      console.warn("verifyToken: Invalid or missing user data in token payload:", { userId, userEmail, userRole });
      return null;
    }

    return {
      id: userId,
      email: userEmail,
      name: decoded.name || null,
      role: userRole as "ADMIN" | "USER",
    };
  } catch (error) {
     if (error instanceof jwt.TokenExpiredError) {
        console.warn("verifyToken: JWT TokenExpiredError:", error.message);
    } else if (error instanceof jwt.JsonWebTokenError) {
        console.warn("verifyToken: JWT JsonWebTokenError (e.g., invalid signature):", error.message);
    } else {
        console.error("verifyToken: Unknown error during token verification:", error);
    }
    return null;
  }
}

export async function getCurrentUser(): Promise<User | null> {
  try {
    const cookieStore = cookies();
    const token = cookieStore.get("auth-token")?.value;

    if (!token) {
      return null;
    }

    const user = verifyToken(token);
    return user; // Tidak perlu cek database lagi jika token valid dan payload cukup
  } catch (error) {
    console.error("getCurrentUser error:", error);
    return null;
  }
}

export async function getUser(): Promise<User | null> {
  return getCurrentUser();
}

export async function requireAuth(): Promise<User> {
  const user = await getCurrentUser();
  if (!user) {
    redirect("/login"); // Path default jika tidak ada callbackUrl
  }
  return user;
}

export async function requireAdmin(): Promise<User> {
  const user = await requireAuth();
  if (user.role !== "ADMIN") {
    redirect("/"); // Redirect ke halaman utama jika bukan admin
  }
  return user;
}
