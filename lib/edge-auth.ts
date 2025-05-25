// lib/edge-auth.ts
import { jwtVerify } from "jose";

// Enhanced JWT verification for Edge Runtime
export async function verifyJWT(token: string, secretInput?: string): Promise<any> {
  try {
    const secretToUse = secretInput || process.env.JWT_SECRET;
    if (!secretToUse) {
      console.error("verifyJWT Error: JWT_SECRET is not defined in environment and not provided as argument.");
      // Jangan throw error di sini agar middleware bisa menangani redirect, tapi pastikan ini tidak terjadi di produksi
      // dengan mengatur JWT_SECRET di environment.
      // Untuk development, ini mungkin terjadi jika JWT_SECRET tidak di-set dan tidak ada fallback.
      // Dalam konteks middleware, kita ingin middleware mengarahkan ke login jika secret tidak ada.
      return null; // Kembalikan null agar middleware bisa redirect.
    }

    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secretToUse);

    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ["HS256"],
      clockTolerance: 15, // 15 seconds clock tolerance
    });

    const now = Math.floor(Date.now() / 1000);
    const sevenDaysInSeconds = 7 * 24 * 60 * 60;
    const iat = payload.iat as number;

    if (iat && now - iat > sevenDaysInSeconds) {
      console.warn("verifyJWT: Token is older than 7 days.");
      return null;
    }

    // Validasi tambahan dari lib/auth.ts
    const userId = typeof payload.id === 'string' && payload.id.length > 0 ? payload.id : null;
    const userEmail = typeof payload.email === 'string' && payload.email.length > 0 ? payload.email : null;
    const userRole = typeof payload.role === 'string' && payload.role.length > 0 ? payload.role : null;

    if (!userId || !userEmail || !userRole) {
      console.warn("verifyJWT: Invalid or missing user data in token payload:", { userId, userEmail, userRole });
      return null; // Invalid token payload
    }

    return {
      id: userId,
      email: userEmail,
      name: (payload.name as string) || null,
      role: userRole as "ADMIN" | "USER", // Pastikan role sesuai tipe
    };
  } catch (error) {
    if (error instanceof Error && (error.name === 'JWTExpired' || error.message.includes('expired'))) {
        console.warn("verifyJWT: Token has expired.", error.message);
    } else if (error instanceof Error && error.message.includes('signature')) {
        console.warn("verifyJWT: Token signature verification failed.", error.message);
    } else if (error instanceof Error && error.message.includes('algorithm')) {
        console.warn("verifyJWT: Token algorithm mismatch.", error.message);
    } else {
        // Jangan log error "JWT_SECRET is not configured" jika sudah ditangani di atas
        if (!(error instanceof Error && error.message.includes("JWT_SECRET is not configured"))) {
             console.error("verifyJWT Error during token verification:", error);
        }
    }
    return null;
  }
}
