// app/analysis/[id]/page.tsx
import { Suspense } from "react";
import { PacketAnalysis } from "@/components/packet-analysis"; //
import { AIInsights } from "@/components/ai-insights"; //
import { NetworkGraph } from "@/components/network-graph"; //
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"; //
import { Skeleton } from "@/components/ui/skeleton"; //
import { getCurrentUser, requireAuth } from "@/lib/auth"; //
import { notFound, redirect } from "next/navigation"; ///not-found.tsx]
import db from "@/lib/neon-db"; //
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"; //
import { Button } from "@/components/ui/button"; //
import Link from "next/link";
import { FileSearch, Activity, Brain, AlertCircle } from "lucide-react";

interface AnalysisPageProps {
  params: {
    id: string;
  };
}

export default async function AnalysisPage({ params }: AnalysisPageProps) {
  await requireAuth();
  const { id } = params;
  const user = await getCurrentUser();

  if (!id || !user) {
    console.error("Analysis page error: Missing ID or user", { id, userId: user?.id });
    notFound();
  }

  let pcapFile = null;
  try {
    console.log(`[ANALYSIS_PAGE] Fetching analysis ${id} for user ${user.id}`);
    pcapFile = await db.pcapFile.findFirst({ //
      where: {
        analysisId: id,
        userId: user.id,
      },
    });

    if (!pcapFile) {
      console.error(`[ANALYSIS_PAGE] Analysis not found: ${id} for user ${user.id}`);
      notFound();
    }
    console.log(`[ANALYSIS_PAGE] Analysis found: ${id}, file: ${pcapFile.originalName}`);
  } catch (dbError) {
    console.error("[ANALYSIS_PAGE] Database error fetching analysis:", dbError);
    // Menampilkan pesan error yang lebih informatif
    return (
      <main className="container mx-auto py-10 px-4 flex flex-col items-center justify-center min-h-[calc(100vh-var(--header-height,4rem))]">
        <Card className="w-full max-w-lg shadow-lg">
          <CardHeader className="text-center">
            <AlertCircle className="mx-auto h-12 w-12 text-red-500 mb-3" />
            <CardTitle className="text-2xl text-red-600">Error Loading Analysis</CardTitle>
            <CardDescription className="text-base">
              We encountered a problem trying to load the details for this analysis.
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <p className="text-muted-foreground mb-2">This could be a temporary issue or a problem with the analysis ID.</p>
            {dbError instanceof Error && (
              <p className="text-sm text-red-500 bg-red-50 dark:bg-red-900/30 p-3 rounded-md">Details: {dbError.message}</p>
            )}
            <div className="mt-6 flex justify-center gap-4">
              <Button asChild variant="outline">
                <Link href="/">Return to Dashboard</Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </main>
    );
  }

  return (
    <main className="container mx-auto py-8 px-4 md:px-6">
      <div className="mb-6">
        <h1 className="text-3xl font-bold tracking-tight md:text-4xl">PCAP Analysis Report</h1>
        <p className="text-lg text-muted-foreground mt-1">
          File: <span className="font-medium text-foreground">{pcapFile.originalName || "Unknown"}</span> | Analysis ID: <span className="font-mono text-xs bg-muted dark:bg-slate-700 px-1.5 py-0.5 rounded">{id}</span>
        </p>
      </div>

      <Tabs defaultValue="packets" className="w-full">
        <TabsList className="grid w-full grid-cols-1 sm:grid-cols-3 h-auto sm:h-11 mb-6 rounded-lg shadow-sm">
          <TabsTrigger value="packets" className="py-2.5 text-sm sm:text-base data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-md rounded-md sm:rounded-l-md sm:rounded-r-none">
            <FileSearch className="mr-2 h-5 w-5" /> Packet Analysis
          </TabsTrigger>
          <TabsTrigger value="network" className="py-2.5 text-sm sm:text-base data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-md rounded-md sm:rounded-none">
            <Activity className="mr-2 h-5 w-5" /> Network Graph
          </TabsTrigger>
          <TabsTrigger value="ai" className="py-2.5 text-sm sm:text-base data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-md rounded-md sm:rounded-r-md sm:rounded-l-none">
            <Brain className="mr-2 h-5 w-5" /> AI Insights
          </TabsTrigger>
        </TabsList>

        <TabsContent value="packets" className="mt-0"> {/* mt-0 agar tidak ada jarak tambahan */}
          <Suspense fallback={<AnalysisPageSkeleton />}>
            <PacketAnalysis analysisId={id} />
          </Suspense>
        </TabsContent>

        <TabsContent value="network" className="mt-0">
          <Suspense fallback={<AnalysisPageSkeleton />}>
            <NetworkGraph analysisId={id} />
          </Suspense>
        </TabsContent>

        <TabsContent value="ai" className="mt-0">
          <Suspense fallback={<AnalysisPageSkeleton />}>
            <AIInsights analysisId={id} />
          </Suspense>
        </TabsContent>
      </Tabs>
    </main>
  );
}

function AnalysisPageSkeleton() { // Skeleton yang lebih generik untuk seluruh tab content
  return (
    <div className="space-y-8 animate-pulse">
      <div className="space-y-4">
        <Skeleton className="h-10 w-3/4" />
        <Skeleton className="h-6 w-1/2" />
      </div>
      <Card className="shadow-lg">
        <CardHeader>
          <Skeleton className="h-8 w-1/3" />
          <Skeleton className="h-4 w-2/3 mt-1" />
        </CardHeader>
        <CardContent className="space-y-4 p-6">
          <Skeleton className="h-32 w-full" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        </CardContent>
      </Card>
       <Card className="shadow-lg">
        <CardHeader>
          <Skeleton className="h-8 w-1/3" />
        </CardHeader>
        <CardContent className="space-y-4 p-6">
          <Skeleton className="h-40 w-full" />
        </CardContent>
      </Card>
    </div>
  );
}
