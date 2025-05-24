"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { LogOut, Settings, UserIcon, Shield } from "lucide-react"

interface AppUser {
  id: string
  email: string
  name: string | null
  role: "ADMIN" | "USER"
}

export function NavBar() {
  const [user, setUser] = useState<AppUser | null>(null)
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    // Check if user is logged in
    fetchUser()
  }, [])

  const fetchUser = async () => {
    try {
      setLoading(true)
      const response = await fetch("/api/auth/me", {
        credentials: "include", // Important for cookies
        cache: "no-store", // Don't cache this request
        headers: {
          "Cache-Control": "no-cache",
          Pragma: "no-cache",
        },
      })

      if (response.ok) {
        const data = await response.json()
        setUser(data.user)
      } else {
        // If not authenticated, clear any stale user data
        setUser(null)
      }
    } catch (error) {
      console.error("Error fetching user:", error)
      setUser(null)
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "include",
      })

      // Clear user state
      setUser(null)

      // Force a hard navigation to ensure cookies are properly cleared
      window.location.href = "/login"
    } catch (error) {
      console.error("Logout error:", error)
    }
  }

  return (
    <nav className="border-b bg-white">
      <div className="container mx-auto px-4 py-3 flex justify-between items-center">
        <Link href="/" className="text-xl font-bold flex items-center">
          <Shield className="h-5 w-5 mr-2" />
          PCAP Scanner
        </Link>

        <div className="flex items-center space-x-4">
          {loading ? (
            <span className="text-sm text-gray-400">Loading...</span>
          ) : user ? (
            <>
              <span className="text-sm text-gray-600">{user.name || user.email.split("@")[0]}</span>

              {user.role === "ADMIN" && (
                <Link href="/admin">
                  <Button variant="outline" size="sm">
                    <Settings className="mr-2 h-4 w-4" />
                    Admin
                  </Button>
                </Link>
              )}

              <Button variant="outline" size="sm" onClick={handleLogout}>
                <LogOut className="mr-2 h-4 w-4" />
                Logout
              </Button>
            </>
          ) : (
            <Link href="/login">
              <Button>
                <UserIcon className="mr-2 h-4 w-4" />
                Login
              </Button>
            </Link>
          )}
        </div>
      </div>
    </nav>
  )
}
