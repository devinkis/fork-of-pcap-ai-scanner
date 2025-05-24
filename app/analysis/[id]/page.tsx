import { Suspense } from "react"
import { PacketAnalysis } from "@/components/packet-analysis"
import { AIInsights } from "@/components/ai-insights"
import { NetworkGraph } from "@/components/network-graph"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Skeleton } from "@/components/ui/skeleton"
import { getCurrentUser, requireAuth } from "@/lib/auth"
import { notFound } from "next/navigation"
import db from "@/lib/neon-db"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import Link from "next/link"

interface AnalysisPageProps {
  params: {
    id: string
  }
}

export default async function AnalysisPage({ params }: AnalysisPageProps) {
  // Ensure user is authenticated
  await requireAuth()

  const { id } = params
  const user = await getCurrentUser()

  if (!id || !user) {
    console.error("Analysis page error: Missing ID or user", { id, userId: user?.id })
    notFound()
  }

  try {
    console.log(`Fetching analysis ${id} for user ${user.id}`)

    // Check if this analysis exists and belongs to the current user
    // Try multiple methods to find the record
    let pcapFile = null

    // Method 1: findFirst with both conditions
    try {
      pcapFile = await db.pcapFile.findFirst({
        where: {
          analysisId: id,
          userId: user.id,
        },
      })
      if (pcapFile) {
        console.log(`✅ Found analysis using findFirst: ${id}`)
      }
    } catch (error) {
      console.warn("Method 1 (findFirst) failed:", error)
    }

    // Method 2: findUnique with just analysis ID if method 1 failed
    if (!pcapFile) {
      try {
        const tempFile = await db.pcapFile.findUnique({
          where: {
            analysisId: id,
          },
        })
        // Check if it belongs to the current user
        if (tempFile && tempFile.userId === user.id) {
          pcapFile = tempFile
          console.log(`✅ Found analysis using findUnique: ${id}`)
        }
      } catch (error) {
        console.warn("Method 2 (findUnique) failed:", error)
      }
    }

    // Method 3: Search through all user files if previous methods failed
    if (!pcapFile) {
      try {
        const allUserFiles = await db.pcapFile.findMany({
          where: { userId: user.id },
        })
        pcapFile = allUserFiles.find((file) => file.analysisId === id) || null
        if (pcapFile) {
          console.log(`✅ Found analysis using findMany: ${id}`)
        }
      } catch (error) {
        console.warn("Method 3 (findMany) failed:", error)
      }
    }

    // If no results, this analysis doesn't exist or doesn't belong to the user
    if (!pcapFile) {
      console.error(`Analysis not found: ${id} for user ${user.id}`)

      // Debug: Show what analyses this user does have
      try {
        const userAnalyses = await db.pcapFile.findMany({
          where: { userId: user.id },
        })
        console.log(
          `User ${user.id} has ${userAnalyses.length} analyses:`,
          userAnalyses.map((f) => ({ id: f.analysisId, name: f.originalName })),
        )
      } catch (debugError) {
        console.warn("Could not fetch user analyses for debugging:", debugError)
      }

      notFound()
    }

    console.log(`Analysis found: ${id}, file: ${pcapFile.originalName}`)

    return (
      <main className="container mx-auto py-10 px-4">
        <h1 className="text-3xl font-bold mb-2">PCAP Analysis</h1>
        <p className="text-muted-foreground mb-6">
          Analysis ID: {id} | File: {pcapFile.originalName || "Unknown"}
        </p>

        <Tabs defaultValue="packets">
          <TabsList className="mb-4">
            <TabsTrigger value="packets">Packet Analysis</TabsTrigger>
            <TabsTrigger value="network">Network Graph</TabsTrigger>
            <TabsTrigger value="ai">AI Insights</TabsTrigger>
          </TabsList>

          <TabsContent value="packets">
            <Suspense fallback={<AnalysisSkeleton />}>
              <PacketAnalysis analysisId={id} />
            </Suspense>
          </TabsContent>

          <TabsContent value="network">
            <Suspense fallback={<AnalysisSkeleton />}>
              <NetworkGraph analysisId={id} />
            </Suspense>
          </TabsContent>

          <TabsContent value="ai">
            <Suspense fallback={<AnalysisSkeleton />}>
              <AIInsights analysisId={id} />
            </Suspense>
          </TabsContent>
        </Tabs>
      </main>
    )
  } catch (error) {
    console.error("Error fetching analysis:", error)
    return (
      <main className="container mx-auto py-10 px-4">
        <Alert variant="destructive" className="mb-6">
          <AlertTitle className="text-xl">Error Loading Analysis</AlertTitle>
          <AlertDescription className="mt-2">
            <p className="mb-4">We encountered an error while loading your analysis data.</p>
            <p className="text-sm mb-4">Error details: {error instanceof Error ? error.message : "Unknown error"}</p>
            <div className="flex gap-4 mt-4">
              <Button asChild variant="outline">
                <Link href="/">Return to Dashboard</Link>
              </Button>
              <Button asChild>
                <Link href="/database-status">Check Database Status</Link>
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      </main>
    )
  }
}

function AnalysisSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-full max-w-md" />
      <div className="grid gap-4 md:grid-cols-3">
        <Skeleton className="h-40" />
        <Skeleton className="h-40" />
        <Skeleton className="h-40" />
      </div>
      <Skeleton className="h-[400px]" />
    </div>
  )
}
