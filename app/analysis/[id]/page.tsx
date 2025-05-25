// app/analysis/[id]/page.tsx
"use client";

import { Suspense, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { PacketAnalysis } from "@/components/packet-analysis";
import { AIInsights } from "@/components/ai-insights";
import { NetworkGraph } from "@/components/network-graph";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { FileSearch, Activity, Brain, AlertCircle, Trash2, Loader2 } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { useToast } from "@/components/ui/use-toast"; // Impor useToast
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"; // Impor Card


interface AnalysisPageProps {
  params: {
    id: string;
  };
}

interface PcapFileDetails {
  originalName: string | null;
  analysisId: string;
}

export default function AnalysisPage({ params }: AnalysisPageProps) {
  const { id: analysisId } = params;
  const router = useRouter();
  const { toast } = useToast(); // Panggil useToast hook
  const [pcapFileDetails, setPcapFileDetails] = useState<PcapFileDetails | null>(null);
  const [isLoadingFileDetails, setIsLoadingFileDetails] = useState(true);
  const [errorFileDetails, setErrorFileDetails] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    async function fetchPcapDetails() {
      if (!analysisId) return;
      setIsLoadingFileDetails(true);
      setErrorFileDetails(null);
      try {
        const response = await fetch(`/api/get-pcap/${analysisId}`);
        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || `Failed to fetch PCAP details: ${response.statusText}`);
        }
        const data = await response.json();
        if (data.success && data.files && data.files.length > 0) {
          setPcapFileDetails({
            originalName: data.files[0].metadata?.originalName || data.files[0].pathname.split('/').pop() || "Unknown File",
            analysisId: analysisId,
          });
        } else {
          throw new Error(data.error || "PCAP file details not found.");
        }
      } catch (err) {
        console.error("Error fetching PCAP details for page:", err);
        setErrorFileDetails(err instanceof Error ? err.message : "Could not load file details.");
      } finally {
        setIsLoadingFileDetails(false);
      }
    }
    fetchPcapDetails();
  }, [analysisId]);


  const handleDeleteAnalysis = async () => {
    setIsDeleting(true);
    try {
      const response = await fetch(`/api/delete-pcap/${analysisId}`, {
        method: 'DELETE',
      });
      const result = await response.json();
      if (!response.ok || !result.success) {
        throw new Error(result.error || "Failed to delete analysis.");
      }
      toast({
        title: "Analysis Deleted",
        description: `Analysis for ${pcapFileDetails?.originalName || analysisId} has been successfully deleted.`,
        variant: "default",
      });
      router.push("/"); 
    } catch (err) {
      console.error("Error deleting analysis:", err);
      toast({
        title: "Error Deleting Analysis",
        description: err instanceof Error ? err.message : "An unexpected error occurred.",
        variant: "destructive",
      });
    } finally {
      setIsDeleting(false);
    }
  };

  if (isLoadingFileDetails) {
    return (
      <main className="container mx-auto py-8 px-4 md:px-6">
        <Skeleton className="h-10 w-3/4 mb-2" />
        <Skeleton className="h-6 w-1/2 mb-6" />
        <Skeleton className="h-10 w-full rounded-lg mb-6" />
        <AnalysisPageSkeleton />
      </main>
    );
  }

  if (errorFileDetails) {
    return (
      <main className="container mx-auto py-10 px-4 flex flex-col items-center justify-center min-h-[calc(100vh-var(--header-height,4rem))]">
        <Card className="w-full max-w-lg shadow-lg">
          <CardHeader className="text-center">
            <AlertCircle className="mx-auto h-12 w-12 text-red-500 mb-3" />
            <CardTitle className="text-2xl text-red-600">Error Loading Analysis Details</CardTitle>
          </CardHeader>
          <CardContent className="text-center">
            <p className="text-muted-foreground mb-2">{errorFileDetails}</p>
            <p className="text-sm">Analysis ID: <span className="font-mono bg-muted dark:bg-slate-700 px-1 py-0.5 rounded">{analysisId}</span></p>
            <div className="mt-6 flex justify-center gap-4">
              <Button asChild variant="outline"><Link href="/">Return to Dashboard</Link></Button>
            </div>
          </CardContent>
        </Card>
      </main>
    );
  }

  return (
    <main className="container mx-auto py-8 px-4 md:px-6">
      <div className="mb-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight md:text-4xl">PCAP Analysis Report</h1>
          <p className="text-lg text-muted-foreground mt-1">
            File: <span className="font-medium text-foreground">{pcapFileDetails?.originalName || "Loading..."}</span> | Analysis ID: <span className="font-mono text-xs bg-muted dark:bg-slate-700 px-1.5 py-0.5 rounded">{analysisId}</span>
          </p>
        </div>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="destructive" disabled={isDeleting}>
              {isDeleting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
              Delete Analysis
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
              <AlertDialogDescription>
                This action cannot be undone. This will permanently delete the
                PCAP analysis record and the associated file from storage.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={isDeleting}>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={handleDeleteAnalysis} disabled={isDeleting} className="bg-destructive hover:bg-destructive/90 text-destructive-foreground">
                {isDeleting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Yes, delete it
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
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

        <TabsContent value="packets" className="mt-0">
          <Suspense fallback={<AnalysisPageSkeleton />}>
            <PacketAnalysis analysisId={analysisId} />
          </Suspense>
        </TabsContent>
        <TabsContent value="network" className="mt-0">
          <Suspense fallback={<AnalysisPageSkeleton />}>
            <NetworkGraph analysisId={analysisId} />
          </Suspense>
        </TabsContent>
        <TabsContent value="ai" className="mt-0">
          <Suspense fallback={<AnalysisPageSkeleton />}>
            <AIInsights analysisId={analysisId} />
          </Suspense>
        </TabsContent>
      </Tabs>
    </main>
  );
}

function AnalysisPageSkeleton() { 
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
