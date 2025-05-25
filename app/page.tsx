// app/page.tsx
import { Suspense } from 'react'
import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { PlusCircle, DatabaseBackup, AlertCircle, CheckCircle, Clock } from 'lucide-react'
import { getUser } from '@/lib/auth' 
import ListChecks from "../components/list-checks"; // DIHAPUS - Karena berkas tidak ada
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { getAnalysesCount, getRecentAnalyses, getStatusCounts } from '@/lib/actions/analysis.actions' // DIHAPUS - Karena berkas tidak ada
import { Analysis } from '@/lib/definitions' // DIHAPUS - Karena berkas tidak ada
import { formatDistanceToNow } from 'date-fns' // Ini adalah paket yang valid, biarkan
import { Badge } from '@/components/ui/badge'

// Helper to determine badge variant based on status - DIPINDAHKAN KE SINI JIKA DIPERLUKAN NANTI ATAU DIHAPUS
// const getStatusVariant = (status: string): "default" | "secondary" | "destructive" | "outline" => {
//   switch (status?.toLowerCase()) { 
//     case 'completed':
//       return 'default'; 
//     case 'processing':
//     case 'pending':
//       return 'secondary'; 
//     case 'error':
//       return 'destructive'; 
//     default:
//       return 'outline';
//   }
// };

// Komponen StatsCards akan di-dummy atau dihapus jika datanya tidak bisa didapatkan
async function StatsCards() {
  // Karena getAnalysesCount dan getStatusCounts tidak ada, kita tampilkan data statis atau pesan
  // try {
  //   const totalAnalyses = await getAnalysesCount();
  //   const statusCounts = await getStatusCounts();

    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Analyses</CardTitle>
            <DatabaseBackup className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {/* <div className="text-2xl font-bold">{totalAnalyses}</div> */}
            <div className="text-2xl font-bold">N/A</div>
            <p className="text-xs text-muted-foreground">
              Overall analyses performed
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Completed</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            {/* <div className="text-2xl font-bold">{statusCounts.completed || 0}</div> */}
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
            {/* <div className="text-2xl font-bold">{(statusCounts.processing || 0) + (statusCounts.pending || 0)}</div> */}
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
            {/* <div className="text-2xl font-bold">{statusCounts.error || 0}</div> */}
            <div className="text-2xl font-bold">N/A</div>
            <p className="text-xs text-muted-foreground">Failed analyses</p>
          </CardContent>
        </Card>
      </div>
    );
  // } catch (error) {
  //   console.error("Error fetching stats for StatsCards:", error);
  //   return <div className="text-red-500">Could not load dashboard statistics.</div>;
  // }
}


// Komponen RecentAnalysesTable akan di-dummy atau dihapus jika datanya tidak bisa didapatkan
async function RecentAnalysesTable() {
  // Karena getRecentAnalyses dan tipe Analysis tidak ada, kita tampilkan data statis atau pesan
  // try {
  //   const recentAnalyses: Analysis[] = await getRecentAnalyses(5); 

  //   if (!recentAnalyses || recentAnalyses.length === 0) {
  //     return <p className="text-sm text-muted-foreground">No recent analyses found.</p>;
  //   }

    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Analyses</CardTitle>
          <CardDescription>A quick look at your latest PCAP file analyses. (Data not available)</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">Recent analyses data cannot be loaded because required modules are missing.</p>
          {/* <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">File Name</th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Uploaded</th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                {recentAnalyses.map((analysis) => (
                  <tr key={analysis.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white truncate max-w-xs" title={analysis.file_name || 'N/A'}>
                      {analysis.file_name || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <Badge variant={getStatusVariant(analysis.status || 'unknown')}>
                        {analysis.status || 'Unknown'}
                      </Badge>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {analysis.upload_date ? formatDistanceToNow(new Date(analysis.upload_date), { addSuffix: true }) : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <Link href={`/analysis/${analysis.id}`} legacyBehavior>
                        <a className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300">View Details</a>
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div> */}
        </CardContent>
      </Card>
    );
  // } catch (error) {
  //   console.error("Error fetching recent analyses for RecentAnalysesTable:", error);
  //   return <div className="text-red-500">Could not load recent analyses.</div>;
  // }
}


export default async function DashboardPage() {
  const user = await getUser(); 

  return (
    <div className="flex min-h-screen w-full flex-col bg-muted/40">
      <main className="flex flex-1 flex-col gap-4 p-4 md:gap-8 md:p-8">
        <div className="flex items-center justify-between space-y-2">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Welcome back, {user?.name || user?.email || 'User'}!</h1>
            <p className="text-muted-foreground">
              Here&apos;s an overview of your PCAP analysis activity.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Link href="/upload">
              <Button>
                <PlusCircle className="mr-2 h-4 w-4" /> Upload New PCAP
              </Button>
            </Link>
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
                Browse and manage all your uploaded PCAP analyses. (Feature currently unavailable)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Suspense fallback={<ListChecksSkeleton />}>
                {/* <ListChecks /> */} {/* DIHAPUS - Karena berkas komponen tidak ada */}
                <p className="text-sm text-muted-foreground">The functionality to list all analysis records is currently unavailable because required modules are missing.</p>
              </Suspense>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}

// Skeleton components tetap bisa digunakan
function DashboardSkeleton() {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {[...Array(4)].map((_, i) => (
        <Card key={i}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div className="h-4 w-2/4 bg-muted rounded animate-pulse"></div>
            <div className="h-4 w-4 bg-muted rounded-full animate-pulse"></div>
          </CardHeader>
          <CardContent>
            <div className="h-7 w-1/4 bg-muted rounded animate-pulse mb-1"></div>
            <div className="h-3 w-3/4 bg-muted rounded animate-pulse"></div>
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
        <div className="h-6 w-1/3 bg-muted rounded animate-pulse"></div>
        <div className="h-4 w-2/3 bg-muted rounded animate-pulse mt-1"></div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="flex items-center justify-between p-2 border-b border-muted">
              <div className="space-y-1">
                <div className="h-4 w-32 bg-muted rounded animate-pulse"></div>
                <div className="h-3 w-20 bg-muted rounded animate-pulse"></div>
              </div>
              <div className="h-4 w-24 bg-muted rounded animate-pulse"></div>
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
      <div className="h-8 w-full bg-muted rounded animate-pulse"></div>
      {[...Array(5)].map((_, i) => (
        <div key={i} className="p-4 border rounded-lg bg-muted/50 animate-pulse">
          <div className="flex justify-between items-center">
            <div className="h-5 w-2/5 bg-background rounded"></div>
            <div className="h-4 w-1/5 bg-background rounded"></div>
          </div>
          <div className="mt-2 h-3 w-3/5 bg-background rounded"></div>
        </div>
      ))}
    </div>
  )
}
