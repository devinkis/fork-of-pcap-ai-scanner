import { type NextRequest, NextResponse } from "next/server"
import db from "@/lib/neon-db"
import { requireAdmin, hashPassword } from "@/lib/auth"

export const runtime = 'nodejs';
export async function PUT(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    await requireAdmin()

    const { email, name, password, role } = await request.json()
    const userId = params.id

    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 })
    }

    // Check if email is already taken by another user
    const existingUser = await db.user.findFirst({
      where: {
        email,
        NOT: { id: userId },
      },
    })

    if (existingUser) {
      return NextResponse.json({ error: "Email is already taken" }, { status: 400 })
    }

    // Prepare update data
    const updateData: any = {
      email,
      name: name || null,
      role: role || "USER",
    }

    // Only update password if provided
    if (password) {
      updateData.password = await hashPassword(password)
    }

    // Update user
    const user = await db.user.update({
      where: { id: userId },
      data: updateData,
    })

    return NextResponse.json({ user })
  } catch (error) {
    console.error("Error updating user:", error)
    return NextResponse.json({ error: "Failed to update user" }, { status: 500 })
  }
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    await requireAdmin()

    const userId = params.id

    // Delete user (this will cascade delete their PCAP files)
    await db.user.delete({
      where: { id: userId },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Error deleting user:", error)
    return NextResponse.json({ error: "Failed to delete user" }, { status: 500 })
  }
}
