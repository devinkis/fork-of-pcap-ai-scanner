import { jwtVerify } from "jose"

// Enhanced JWT verification for Edge Runtime
export async function verifyJWT(token: string, secret: string): Promise<any> {
  try {
    // Use jose library which is compatible with Edge Runtime
    const encoder = new TextEncoder()
    const secretKey = encoder.encode(secret)

    // Add more strict verification options
    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ["HS256"],
      clockTolerance: 15, // 15 seconds clock tolerance
    })

    // Check if token was issued too long ago (force re-login after 7 days regardless)
    const now = Math.floor(Date.now() / 1000)
    const sevenDaysInSeconds = 7 * 24 * 60 * 60
    const iat = payload.iat as number

    if (iat && now - iat > sevenDaysInSeconds) {
      return null
    }

    return {
      id: payload.id as string,
      email: payload.email as string,
      name: (payload.name as string) || null,
      role: payload.role as string,
    }
  } catch (error) {
    return null
  }
}
