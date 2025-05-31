// app/page.tsx
import Link from "next/link";
import { Suspense } from "react";
import { Button } from "@/components/ui/button";
import { 
    Card, CardContent, CardDescription, 
    CardFooter, CardHeader, CardTitle 
} from "@/components/ui/card";
import { 
    Table, TableBody, TableCell, TableHead, 
    TableHeader, TableRow 
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { 
    AlertCircle, FileText, BarChart2, Shield, Network, 
    UploadCloud, PlusCircle, ListChecks as ListChecksIcon, UserCircle, Trash2, Loader2 // Tambahkan ikon
} from "lucide-react";
import { PcapUploader } from "@/components/pcap-uploader";
import { getCurrentUser } from "@/lib/auth"; // Untuk mendapatkan info user
//import { getPcapAnalysesForUser, PcapAnalysisRecord } from "@/lib/actions/analysis.actions"; // Asumsi fungsi ini ada
import { 
  getPcapAnalysesForUser,
  getAnalysesCount, 
  getRecentAnalyses, 
  getStatusCounts 
} from '@/lib/actions/analysis.actions';
import { Analysis } from '@/lib/definitions'; // Pastikan Analysis juga diekspor dari lib/definitions.ts
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
} from "@/components/ui/alert-dialog"; // Impor AlertDialog
import { DeleteAllAnalysesButton } from "@/components/delete-all-analyses-button"; // Komponen baru (akan kita buat)


async function AnalysisListSkeleton() {
  return (
    <Card className="shadow-lg col-span-1 lg:col-span-3">
      <CardHeader>
        <CardTitle className="flex items-center text-2xl">
          <ListChecksIcon className="mr-3 h-7 w-7 text-primary" />
          My PCAP Analyses
        </CardTitle>
        <CardDescription>
          View and manage your uploaded PCAP file analyses. Loading...
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="flex items-center justify-between p-3 border rounded-md animate-pulse">
              <div className="space-y-1">
                <div className="h-4 bg-gray-300 dark:bg-gray-700 rounded w-3/4"></div>
                <div className="h-3 bg-gray-300 dark:bg-gray-700 rounded w-1/2"></div>
              </div>
              <div className="h-8 bg-gray-300 dark:bg-gray-700 rounded w-20"></div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

async function PcapAnalysesList({ userId }: { userId: string }) {
  let analyses: PcapAnalysisRecord[] = [];
  let error: string | null = null;

  try {
    analyses = await getPcapAnalysesForUser(userId);
  } catch (err) {
    console.error("Failed to fetch analyses:", err);
    error = err instanceof Error ? err.message : "Could not load analyses.";
  }

  if (error) {
    return (
      <Card className="shadow-lg col-span-1 lg:col-span-3">
        <CardHeader>
          <CardTitle className="flex items-center text-2xl">
            <AlertCircle className="mr-3 h-7 w-7 text-destructive" />
            Error Loading Analyses
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-destructive">{error}</p>
          <p className="text-sm text-muted-foreground mt-1">Please try refreshing the page or check back later.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="shadow-lg col-span-1 lg:col-span-3">
      <CardHeader className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
        <div>
            <CardTitle className="flex items-center text-2xl">
            <ListChecksIcon className="mr-3 h-7 w-7 text-primary" />
            My PCAP Analyses
            </CardTitle>
            <CardDescription>
            View and manage your uploaded PCAP file analyses.
            </CardDescription>
        </div>
        {analyses.length > 0 && <DeleteAllAnalysesButton />} 
      </CardHeader>
      <CardContent>
        {analyses.length === 0 ? (
          <div className="text-center py-10 text-muted-foreground">
            <FileText className="mx-auto h-12 w-12 mb-3" />
            <p>No PCAP analyses found.</p>
            <p className="text-sm">Upload a PCAP file to get started.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>File Name</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Uploaded At</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {analyses.map((analysis) => (
                  <TableRow key={analysis.analysisId}>
                    <TableCell className="font-medium max-w-xs truncate" title={analysis.originalName}>
                      {analysis.originalName}
                    </TableCell>
                    <TableCell>{(analysis.size / (1024 * 1024)).toFixed(2)} MB</TableCell>
                    <TableCell>{new Date(analysis.createdAt).toLocaleDateString()}</TableCell>
                    <TableCell>
                      <Badge variant={analysis.status === 'Completed' ? 'success' : analysis.status === 'Processing' ? 'secondary' : 'outline'}>
                        {analysis.status || "Unknown"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button asChild variant="ghost" size="sm">
                        <Link href={`/analysis/${analysis.analysisId}`}>View</Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
       {analyses.length > 0 && (
        <CardFooter className="text-sm text-muted-foreground">
          You have {analyses.length} analysis record{analyses.length === 1 ? "" : "s"}.
        </CardFooter>
      )}
    </Card>
  );
}


export default async function DashboardPage() {
  const user = await getCurrentUser();

  return (
    <div className="flex flex-col min-h-screen">
      <main className="flex-grow container mx-auto py-8 px-4 md:px-6 space-y-10">
        <section className="text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4">
            PCAP Analysis <span className="text-primary">Dashboard</span>
          </h1>
          <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-8">
            Upload your PCAP files for in-depth network traffic analysis, threat detection, and AI-powered insights.
          </p>
           {!user && (
            <Button size="lg" asChild>
              <Link href="/login">Get Started - Login</Link>
            </Button>
          )}
        </section>

        {user && (
          <section className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
            <Card className="shadow-lg col-span-1 lg:col-span-3 xl:col-span-2 order-2 lg:order-1">
                <CardHeader>
                    <CardTitle className="flex items-center text-2xl">
                        <UploadCloud className="mr-3 h-7 w-7 text-primary" />
                        Upload New PCAP File
                    </CardTitle>
                    <CardDescription>
                        Drag and drop your .pcap, .pcapng, or .cap file here, or click to select a file. Max file size: 50MB.
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <PcapUploader />
                </CardContent>
            </Card>
            <Card className="shadow-lg col-span-1 lg:col-span-3 xl:col-span-1 order-1 lg:order-2 bg-gradient-to-br from-primary/90 to-primary/70 text-primary-foreground">
                <CardHeader>
                    <UserCircle className="h-10 w-10 mb-3 text-primary-foreground/80"/>
                    <CardTitle className="text-2xl">Welcome, {user.name || user.email}!</CardTitle>
                    <CardDescription className="text-primary-foreground/90">
                        Manage your analyses or upload a new file to begin.
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                    <div className="flex items-center justify-between p-3 bg-black/10 rounded-lg">
                        <div>
                            <p className="text-sm">Analyses Count</p>
                            <p className="text-2xl font-bold">
                                <Suspense fallback={<span>...</span>}>
                                    <UserAnalysesCount userId={user.id!} />
                                </Suspense>
                            </p>
                        </div>
                        <ListChecksIcon className="h-8 w-8 text-primary-foreground/70"/>
                    </div>
                </CardContent>
                 <CardFooter>
                    <Button variant="secondary" className="w-full bg-primary-foreground text-primary hover:bg-primary-foreground/90" asChild>
                       <Link href="/analysis">View All My Analyses</Link>
                    </Button>
                </CardFooter>
            </Card>
          </section>
        )}
        
        {user && user.id && (
          <section>
            <Suspense fallback={<AnalysisListSkeleton />}>
              <PcapAnalysesList userId={user.id} />
            </Suspense>
          </section>
        )}

        {!user && (
           <section className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12 text-center">
            <Card className="shadow-md hover:shadow-lg transition-shadow">
              <CardHeader><Network className="mx-auto h-10 w-10 text-primary mb-2"/><CardTitle>Deep Packet Inspection</CardTitle></CardHeader>
              <CardContent><p className="text-sm text-muted-foreground">Analyze network protocols, conversations, and potential anomalies.</p></CardContent>
            </Card>
            <Card className="shadow-md hover:shadow-lg transition-shadow">
              <CardHeader><Shield className="mx-auto h-10 w-10 text-primary mb-2"/><CardTitle>Threat Intelligence</CardTitle></CardHeader>
              <CardContent><p className="text-sm text-muted-foreground">Correlate IOCs with known threat feeds for rapid detection.</p></CardContent>
            </Card>
            <Card className="shadow-md hover:shadow-lg transition-shadow">
              <CardHeader><BarChart2 className="mx-auto h-10 w-10 text-primary mb-2"/><CardTitle>AI-Powered Insights</CardTitle></CardHeader>
              <CardContent><p className="text-sm text-muted-foreground">Get summaries, recommendations, and behavioral analysis from our AI.</p></CardContent>
            </Card>
          </section>
        )}
      </main>
       <footer className="text-center py-6 border-t dark:border-slate-700">
          <p className="text-sm text-muted-foreground">&copy; {new Date().getFullYear()} PCAP AI Scanner. All rights reserved.</p>
      </footer>
    </div>
  );
}


async function UserAnalysesCount({ userId }: { userId: string }) {
  try {
    const analyses = await getPcapAnalysesForUser(userId);
    return <>{analyses.length}</>;
  } catch {
    return <>0</>;
  }
}
