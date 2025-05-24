import { getUser } from "@/lib/auth"
import { UserManagement } from "@/components/user-management"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { redirect } from "next/navigation"

export default async function AdminPage() {
  // Get the user without redirecting
  const user = await getUser()

  // If no user or not admin, redirect manually
  if (!user) {
    redirect("/login")
  }

  if (user.role !== "ADMIN") {
    redirect("/")
  }

  return (
    <main className="container mx-auto py-10 px-4">
      <h1 className="text-3xl font-bold mb-6">Admin Dashboard</h1>

      <Card>
        <CardHeader>
          <CardTitle>User Management</CardTitle>
        </CardHeader>
        <CardContent>
          <UserManagement />
        </CardContent>
      </Card>
    </main>
  )
}
