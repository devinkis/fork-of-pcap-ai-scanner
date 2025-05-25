// components/list-checks.tsx
"use client"; // Komponen ini mungkin memerlukan interaktivitas atau hook sisi klien

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AlertTriangle, FileText, Eye, Loader2, RefreshCw } from "lucide-react";
import { formatDistanceToNow } from 'date-fns';
// import { Analysis } from '@/lib/definitions'; // Jika Anda membuat tipe ini lebih detail

// Definisikan tipe sementara di sini jika lib/definitions belum mencakup semua
interface PcapAnalysisRecord {
  id: string; // analysisId
  originalName: string | null;
  createdAt: string; // ISO String date
  status?: 'COMPLETED' | 'PROCESSING' | 'PENDING' | 'ERROR' | 'UNKNOWN'; // Opsional, untuk tampilan
  // Tambahkan field lain yang mungkin dikembalikan oleh API Anda
  fileName?: string; // Ini mungkin nama berkas di blob storage
  size?: number;
  userId?: string;
}

// Fungsi helper untuk varian badge status
const getStatusVariant = (status?: string): "default" | "secondary" | "destructive" | "outline" => {
  switch (status?.toLowerCase()) {
    case 'completed':
      return 'default'; // Atau 'success' jika Anda punya varian itu
    case 'processing':
    case 'pending':
      return 'secondary';
    case 'error':
      return 'destructive';
    default:
      return 'outline';
  }
};


export default function ListChecks() {
  const [analyses, setAnalyses] = useState<PcapAnalysisRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAnalyses = async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Anda perlu API endpoint untuk mengambil semua analisis untuk pengguna saat ini
      // Contoh: /api/analyses (Anda perlu membuat API route ini)
      // Untuk sekarang, kita akan menggunakan /api/debug karena itu mengembalikan pcapFiles.userFiles
      // Namun, idealnya, Anda harus membuat endpoint khusus.
      const response = await fetch('/api/debug'); // GANTILAH DENGAN ENDPOINT YANG SESUAI
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Failed to fetch analyses: ${response.statusText}`);
      }
      const data = await response.json();
      // Sesuaikan ini berdasarkan struktur respons dari /api/debug atau API Anda
      if (data.pcapFiles && data.pcapFiles.userFiles) {
         // Mapping data dari /api/debug ke PcapAnalysisRecord
        const mappedData: PcapAnalysisRecord[] = data.pcapFiles.userFiles.map((file: any) => ({
            id: file.analysisId, // Menggunakan analysisId sebagai ID utama untuk link
            originalName: file.originalName,
            createdAt: file.createdAt,
            status: (file as any).status || 'UNKNOWN', // Asumsi status, perlu ada di data sebenarnya
            fileName: file.fileName,
            size: file.size,
            userId: file.userId
        }));
        setAnalyses(mappedData);
      } else {
        setAnalyses([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unknown error occurred");
      setAnalyses([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, []);

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-10">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <p className="ml-2">Loading analyses...</p>
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Error Loading Analyses</AlertTitle>
        <AlertDescription>
          {error}
          <Button onClick={fetchAnalyses} variant="link" className="pl-1 text-red-600 dark:text-red-400">
            Try again
          </Button>
        </AlertDescription>
      </Alert>
    );
  }

  if (analyses.length === 0) {
    return (
      <div className="text-center py-10">
        <FileText className="h-12 w-12 mx-auto text-muted-foreground mb-3" />
        <p className="text-muted-foreground">No PCAP analyses found for your account.</p>
        <Button asChild className="mt-4">
          <Link href="/upload">Upload Your First PCAP</Link>
        </Button>
      </div>
    );
  }

  return (
    <Card>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[200px]">File Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="min-w-[150px]">Uploaded</TableHead>
                <TableHead className="min-w-[100px]">Size</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {analyses.map((analysis) => (
                <TableRow key={analysis.id}>
                  <TableCell className="font-medium truncate max-w-xs" title={analysis.originalName || undefined}>
                    {analysis.originalName || "N/A"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={getStatusVariant(analysis.status)}>
                      {analysis.status || "Unknown"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {formatDistanceToNow(new Date(analysis.createdAt), { addSuffix: true })}
                  </TableCell>
                  <TableCell>
                    {analysis.size ? `${(analysis.size / (1024 * 1024)).toFixed(2)} MB` : 'N/A'}
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
