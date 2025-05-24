"use client"

import { useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { useRouter } from "next/navigation"

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // Log the error to an error reporting service
    console.error("Analysis page error:", error)
  }, [error])

  const router = useRouter()

  return (
    <div className="container mx-auto py-10 px-4 flex justify-center">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-red-500">Something went wrong</CardTitle>
        </CardHeader>
        <CardContent>
          <p>There was an error analyzing the PCAP file. This could be due to:</p>
          <ul className="list-disc pl-5 mt-2 space-y-1">
            <li>The file format is not supported or is corrupted</li>
            <li>The analysis service is temporarily unavailable</li>
            <li>There was an issue with the AI processing</li>
          </ul>
          <p className="mt-4 text-sm text-muted-foreground">Error details: {error?.message || "Unknown error"}</p>
        </CardContent>
        <CardFooter className="flex justify-between">
          <Button variant="outline" onClick={() => router.push("/")}>
            Upload New File
          </Button>
          <Button onClick={reset}>Try Again</Button>
        </CardFooter>
      </Card>
    </div>
  )
}
