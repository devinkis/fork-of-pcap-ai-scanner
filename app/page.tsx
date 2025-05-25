// app/page.tsx
"use client"; // Tambahkan ini karena kita akan menggunakan useState untuk Dialog

import { Suspense, useState } from 'react'; // Tambahkan useState
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { PlusCircle, DatabaseBackup, AlertCircle, CheckCircle, Clock } from 'lucide-react';
import { getUser } from '@/lib/auth'; // Ini adalah fungsi async, perlu penanganan jika digunakan di client component
                                     // Atau, lebih baik data user didapatkan di Server Component dan di-pass sebagai props jika page ini menjadi client component
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
// Komentari impor yang menyebabkan error build sebelumnya jika belum diperbaiki
// import { getAnalysesCount, getRecentAnalyses, getStatusCounts } from '@/lib/actions/analysis.actions';
// import { Analysis } from '@/lib/definitions';
import { formatDistanceToNow } from 'date-fns';
import { Badge } from '@/components/ui/badge';

// Impor komponen Dialog dan PcapUploader
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose, // Tambahkan DialogClose jika perlu tombol tutup manual
} from "@/components/ui/dialog";
import { PcapUploader } from '@/components/pcap-uploader'; // Pastikan path ini benar
import { Skeleton } from '@/components/ui/skeleton'; // Untuk fallback Suspense jika getUser masih async

// Untuk StatsCards dan RecentAnalysesTable, kita gunakan versi dummy/placeholder
// Karena getAnalysesCount, getStatusCounts, getRecentAnalyses, dan Analysis di-comment
async function StatsCards() {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Analyses</CardTitle>
            <DatabaseBackup className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">N/A</div>
            <p className="text-xs text-muted-foreground">Overall analyses performed</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Completed</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">N/A</div>
            <p className="text-xs text-muted-foreground">Successfully processed</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Processing/Pending</CardTitle>
            <Clock className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">N/A</div>
            <p className="text-xs text-muted-foreground">Currently in queue or active</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Errors</CardTitle>
            <AlertCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">N/A</div>
            <p className="text-xs text-muted-foreground">Failed analyses</p>
          </CardContent>
        </Card>
      </div>
    );
}

async function RecentAnalysesTable() {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Analyses</CardTitle>
          <CardDescription>A quick look at your latest PCAP file analyses. (Data not available)</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">Recent analyses data cannot be loaded because required modules are missing.</p>
        </CardContent>
      </Card>
    );
}

// Jika DashboardPage adalah Server Component, kita tidak bisa menggunakan useState secara langsung
// Kita perlu membuat komponen klien terpisah untuk Dialog atau menjadikan DashboardPage klien.
// Untuk kesederhanaan, kita jadikan DashboardPage sebagai Client Component.

export default function DashboardPage() {
  // const user = await getUser(); // Ini tidak bisa di Client Component secara langsung
  // Untuk Client Component, data user biasanya diambil melalui useEffect atau context/props
  // Untuk sementara, kita bisa tampilkan nama generik atau loading state untuk user.
  // Solusi yang lebih baik adalah memisahkan pengambilan data user.
  
  const [isUploadDialogOpen, setIsUploadDialogOpen] = useState(false);
  const [userName, setUserName] = useState<string | null>(null);
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [loadingUser, setLoadingUser] = useState(true);

  useEffect(() => {
    async function fetchCurrentUser() {
      try {
        // Asumsi /api/auth/me mengembalikan data user yang login
        const response = await fetch('/api/auth/me');
        if (response.ok) {
          const data = await response.json();
          if (data.user) {
            setUserName(data.user.name);
            setUserEmail(data.user.email);
          }
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
            {/* Tombol untuk memicu Dialog */}
            <Dialog open={isUploadDialogOpen} onOpenChange={setIsUploadDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <PlusCircle className="mr-2 h-4 w-4" /> Upload New PCAP
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-[625px]"> {/* Sesuaikan lebar dialog jika perlu */}
                <DialogHeader>
                  <DialogTitle>Upload PCAP File</DialogTitle>
                  <DialogDescription>
                    Select a .pcap or .pcapng file to upload for analysis. Maximum file size: 50MB.
                  </DialogDescription>
                </DialogHeader>
                <div className="py-4">
                  <PcapUploader />
                </div>
                {/* Anda bisa menambahkan DialogFooter dengan tombol Close jika PcapUploader tidak menutup dialog secara otomatis */}
                {/* <DialogFooter>
                  <DialogClose asChild>
                    <Button type="button" variant="secondary">
                      Close
                    </Button>
                  </DialogClose>
                </DialogFooter> */}
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Suspense dan StatsCards/RecentAnalysesTable akan menggunakan versi dummy */}
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
                Browse and manage all your uploaded PCAP analyses. (Feature currently unavailable)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Suspense fallback={<ListChecksSkeleton />}>
                <p className="text-sm text-muted-foreground">The functionality to list all analysis records is currently unavailable because required modules are missing.</p>
              </Suspense>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}

// Skeleton components tetap sama
function DashboardSkeleton() {
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

function RecentAnalysesSkeleton() {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-6 w-1/3" />
        <Skeleton className="h-4 w-2/3 mt-1" />
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="flex items-center justify-between p-2 border-b">
              <div className="space-y-1">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-3 w-20" />
              </div>
              <Skeleton className="h-4 w-24" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

function ListChecksSkeleton() {
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
