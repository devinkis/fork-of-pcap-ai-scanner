// Path: devinkis/fork-of-pcap-ai-scanner/fork-of-pcap-ai-scanner-fb3444031e0b44895e9fddc8cf7c92cce4812117/app/api/admin/users/route.ts
// --- PERBAIKAN MULAI ---
import db from "@/lib/neon-db" // Mengimpor database Neon
// --- PERBAIKAN SELESAI ---
import { type NextRequest, NextResponse } from "next/server"
import { requireAdmin, hashPassword } from "@/lib/auth"

export const runtime = 'nodejs';
export async function GET() {
  try {
    await requireAdmin()

    const users = await db.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    })

    return NextResponse.json({ users })
  } catch (error) {
    console.error("Error fetching users:", error)
    return NextResponse.json({ error: "Failed to fetch users" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    await requireAdmin()

    const { email, name, password, role } = await request.json()

    if (!email || !password) {
      return NextResponse.json({ error: "Email and password are required" }, { status: 400 })
    }

    // Check if user already exists
    const existingUser = await db.user.findUnique({
      where: { email },
    })

    if (existingUser) {
      return NextResponse.json({ error: "User with this email already exists" }, { status: 400 })
    }

    // Hash password
    const hashedPassword = await hashPassword(password)

    // Create user
    const user = await db.user.create({
      data: {
        email,
        name: name || null,
        password: hashedPassword,
        role: role || "USER",
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    })

    return NextResponse.json({ user })
  } catch (error) {
    console.error("Error creating user:", error)
    return NextResponse.json({ error: "Failed to create user" }, { status: 500 })
  }
}
