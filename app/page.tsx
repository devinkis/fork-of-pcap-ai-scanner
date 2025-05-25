// app/page.tsx
"use client"; 

import React, { Suspense, useState, useEffect } from 'react'; // Pastikan React diimpor jika belum
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { PlusCircle, DatabaseBackup, AlertCircle, CheckCircle, Clock, Eye, Loader2, FileText } from 'lucide-react'; // Tambahkan ikon yang mungkin dibutuhkan
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"; // Untuk RecentAnalysesTable
import { getAnalysesCount, getRecentAnalyses, getStatusCounts } from '@/lib/actions/analysis.actions'; // Pulihkan impor
import { Analysis } from '@/lib/definitions'; // Pulihkan impor
import { formatDistanceToNow } from 'date-fns';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { PcapUploader } from '@/components/pcap-uploader';
import { Skeleton } from '@/components/ui/skeleton';

// Fungsi helper untuk status badge
const getStatusVariant = (status?: string): "default" | "secondary" | "destructive" | "outline" => {
  switch (status?.toLowerCase()) {
    case 'completed':
      return 'default';
    case 'processing':
    case 'pending':
      return 'secondary';
    case 'error':
      return 'destructive';
    default:
      return 'outline';
  }
};

// Komponen StatsCards sebagai Client Component
function StatsCards() {
  const [totalAnalyses, setTotalAnalyses] = useState<number | string>("N/A");
  const [statusCounts, setStatusCounts] = useState<{ completed?: number; processing?: number; pending?: number; error?: number }>({});
  const [loadingStats, setLoadingStats] = useState(true);

  useEffect(() => {
    async function fetchData() {
      setLoadingStats(true);
      try {
        const count = await getAnalysesCount();
        const sCounts = await getStatusCounts();
        setTotalAnalyses(count);
        setStatusCounts(sCounts);
      } catch (error) {
        console.error("Failed to fetch stats for StatsCards:", error);
        setTotalAnalyses("Error");
        setStatusCounts({});
      } finally {
        setLoadingStats(false);
      }
    }
    fetchData();
  }, []);

  if (loadingStats) {
    return <DashboardSkeleton />; // Gunakan skeleton yang sudah ada
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Analyses</CardTitle>
          <DatabaseBackup className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{totalAnalyses}</div>
          <p className="text-xs text-muted-foreground">Overall analyses performed</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Completed</CardTitle>
          <CheckCircle className="h-4 w-4 text-green-500" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{statusCounts.completed || 0}</div>
          <p className="text-xs text-muted-foreground">Successfully processed</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Processing/Pending</CardTitle>
          <Clock className="h-4 w-4 text-blue-500" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{(statusCounts.processing || 0) + (statusCounts.pending || 0)}</div>
          <p className="text-xs text-muted-foreground">Currently in queue or active</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Errors</CardTitle>
          <AlertCircle className="h-4 w-4 text-red-500" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{statusCounts.error || 0}</div>
          <p className="text-xs text-muted-foreground">Failed analyses</p>
        </CardContent>
      </Card>
    </div>
  );
}

// Komponen RecentAnalysesTable sebagai Client Component
function RecentAnalysesTable() {
  const [recentAnalyses, setRecentAnalyses] = useState<Analysis[]>([]);
  const [loadingRecent, setLoadingRecent] = useState(true);
  const [errorRecent, setErrorRecent] = useState<string | null>(null);

  useEffect(() => {
    async function fetchData() {
      setLoadingRecent(true);
      setErrorRecent(null);
      try {
        const analyses = await getRecentAnalyses(5);
        setRecentAnalyses(analyses);
      } catch (error) {
        console.error("Failed to fetch recent analyses:", error);
        setErrorRecent("Could not load recent analyses.");
      } finally {
        setLoadingRecent(false);
      }
    }
    fetchData();
  }, []);

  if (loadingRecent) {
    return <RecentAnalysesSkeleton />; // Gunakan skeleton yang sudah ada
  }

  if (errorRecent) {
    return (
        <Card>
            <CardHeader><CardTitle>Recent Analyses</CardTitle></CardHeader>
            <CardContent><p className="text-sm text-red-500">{errorRecent}</p></CardContent>
        </Card>
    );
  }
  
  if (recentAnalyses.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Analyses</CardTitle>
          <CardDescription>A quick look at your latest PCAP file analyses.</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">No recent analyses found.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Analyses</CardTitle>
        <CardDescription>A quick look at your latest PCAP file analyses.</CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="min-w-[200px]">File Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="min-w-[150px]">Uploaded</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentAnalyses.map((analysis) => (
                  <TableRow key={analysis.id}>
                    <TableCell className="font-medium truncate max-w-xs" title={analysis.file_name || undefined}>
                      {analysis.file_name || 'N/A'}
                    </TableCell>
                    <TableCell>
                      <Badge variant={getStatusVariant(analysis.status || 'unknown')}>
                        {analysis.status || 'Unknown'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {analysis.upload_date ? formatDistanceToNow(new Date(analysis.upload_date), { addSuffix: true }) : 'N/A'}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button asChild variant="outline" size="sm">
                        <Link href={`/analysis/${analysis.id}`}>
                          <Eye className="h-4 w-4 mr-1 sm:mr-2" />
                          View
                        </Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
      </CardContent>
    </Card>
  );
}

// Skeleton components bisa tetap ada
function DashboardSkeleton() { /* ...definisi skeleton sama seperti sebelumnya... */ 
    return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <Skeleton className="h-4 w-2/4" />
                <Skeleton className="h-4 w-4 rounded-full" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-1/4 mb-1" />
                <Skeleton className="h-3 w-3/4" />
              </CardContent>
            </Card>
          ))}
        </div>
      )
}

function RecentAnalysesSkeleton() { /* ...definisi skeleton sama seperti sebelumnya... */ 
    return (
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-1/3" />
            <Skeleton className="h-4 w-2/3 mt-1" />
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex items-center justify-between p-4">
                  <div className="space-y-1">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-3 w-20" />
                  </div>
                  <Skeleton className="h-8 w-20" /> {/* Untuk tombol View */}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )
}

function ListChecksSkeleton() { /* ...definisi skeleton sama seperti sebelumnya... */ 
    return (
        <div className="space-y-4">
          <Skeleton className="h-8 w-full" />
          {[...Array(5)].map((_, i) => (
            <div key={i} className="p-4 border rounded-lg">
              <div className="flex justify-between items-center">
                <Skeleton className="h-5 w-2/5" />
                <Skeleton className="h-4 w-1/5" />
              </div>
              <Skeleton className="mt-2 h-3 w-3/5" />
            </div>
          ))}
        </div>
      )
}

export default function DashboardPage() {
  const [isUploadDialogOpen, setIsUploadDialogOpen] = useState(false);
  const [userName, setUserName] = useState<string | null>(null);
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [loadingUser, setLoadingUser] = useState(true);

  useEffect(() => {
    async function fetchCurrentUser() {
      setLoadingUser(true);
      try {
        const response = await fetch('/api/auth/me');
        if (response.ok) {
          const data = await response.json();
          if (data.user) {
            setUserName(data.user.name);
            setUserEmail(data.user.email);
          } else {
            console.warn("User data not found in /api/auth/me response");
          }
        } else {
          console.error("Failed to fetch user from /api/auth/me, status:", response.status);
        }
      } catch (error) {
        console.error("Failed to fetch user for dashboard:", error);
      } finally {
        setLoadingUser(false);
      }
    }
    fetchCurrentUser();
  }, []);

  return (
    <div className="flex min-h-screen w-full flex-col bg-muted/40">
      <main className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        <div className="flex items-center justify-between space-y-2">
          <div>
            {loadingUser ? (
              <>
                <Skeleton className="h-8 w-48 mb-1" />
                <Skeleton className="h-4 w-64" />
              </>
            ) : (
              <>
                <h1 className="text-3xl font-bold tracking-tight">Welcome back, {userName || userEmail || 'User'}!</h1>
                <p className="text-muted-foreground">
                  Here&apos;s an overview of your PCAP analysis activity.
                </p>
              </>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <Dialog open={isUploadDialogOpen} onOpenChange={setIsUploadDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <PlusCircle className="mr-2 h-4 w-4" /> Upload New PCAP
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-[625px]">
                <DialogHeader>
                  <DialogTitle>Upload PCAP File</DialogTitle>
                  <DialogDescription>
                    Select a .pcap or .pcapng file to upload for analysis. Maximum file size: 50MB.
                  </DialogDescription>
                </DialogHeader>
                <div className="py-4">
                  <PcapUploader />
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        <Suspense fallback={<DashboardSkeleton />}>
          <StatsCards />
        </Suspense>

        <div className="grid gap-4 md:gap-8 lg:grid-cols-2 xl:grid-cols-3">
          <Suspense fallback={<RecentAnalysesSkeleton />}>
            <RecentAnalysesTable />
          </Suspense>
          
          <Card className="xl:col-span-2">
            <CardHeader>
              <CardTitle>All Analysis Records</CardTitle>
              <CardDescription>
                Browse and manage all your uploaded PCAP analyses.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Suspense fallback={<ListChecksSkeleton />}>
                {/* <ListChecks /> akan ditambahkan di sini nanti jika sudah ada */}
                <p className="text-sm text-muted-foreground">
                  The component to list all analysis records (`ListChecks`) is not yet implemented or integrated.
                </p>
              </Suspense>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
