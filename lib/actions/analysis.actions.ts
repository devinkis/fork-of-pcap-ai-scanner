// lib/actions/analysis.actions.ts
"use server"; // Menandakan bahwa fungsi-fungsi ini dapat dijalankan di server (Server Actions)

import db from "@/lib/neon-db"; // Menggunakan koneksi database Neon Anda
import { Analysis } from '@/lib/definitions'; // Mengimpor tipe Analysis
import { getCurrentUser } from '@/lib/auth'; // Untuk mendapatkan pengguna saat ini jika data perlu difilter per pengguna

/**
 * Mengambil jumlah total analisis PCAP yang tersimpan.
 * Jika pengguna diautentikasi, ini bisa difilter berdasarkan userId.
 */
export async function getAnalysesCount(): Promise<number> {
  const user = await getCurrentUser();
  if (!user) {
    console.warn("getAnalysesCount: User not authenticated. Returning 0.");
    return 0;
  }

  try {
    const analyses = await db.pcapFile.findMany({ userId: user.id });
    return analyses.length;
  } catch (error) {
    console.error("Error in getAnalysesCount:", error);
    return 0;
  }
}

/**
 * Mengambil daftar analisis PCAP terbaru.
 * @param limit Jumlah analisis terbaru yang ingin diambil.
 */
export async function getRecentAnalyses(limit: number = 5): Promise<Analysis[]> {
  const user = await getCurrentUser();
  if (!user) {
    console.warn("getRecentAnalyses: User not authenticated. Returning empty array.");
    return [];
  }

  try {
    const recentPcapFiles = await db.pcapFile.findMany({
      userId: user.id,
    });

    // Sortir berdasarkan tanggal pembuatan (createdAt dari PcapFile) secara descending
    const sortedFiles = recentPcapFiles.sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
    
    const limitedFiles = sortedFiles.slice(0, limit);
    
    return limitedFiles.map(file => ({
      id: file.analysisId,
      file_name: file.originalName,
      // Anda perlu menambahkan kolom 'status' ke skema tabel 'pcap_files'
      // atau memiliki cara lain untuk menentukannya.
      status: (file as any).status || 'UNKNOWN', 
      upload_date: file.createdAt.toISOString(), 
    }));
  } catch (error) {
    console.error("Error in getRecentAnalyses:", error);
    return []; 
  }
}

/**
 * Menghitung jumlah analisis berdasarkan statusnya.
 * Ini memerlukan kolom 'status' pada tabel 'pcap_files'.
 */
export async function getStatusCounts(): Promise<{ completed?: number; processing?: number; pending?: number; error?: number; unknown?: number }> {
  const user = await getCurrentUser();
  if (!user) {
    console.warn("getStatusCounts: User not authenticated. Returning empty counts.");
    return { completed: 0, processing: 0, pending: 0, error: 0, unknown: 0 };
  }

  try {
    const allAnalyses = await db.pcapFile.findMany({ userId: user.id });
    const counts: { completed: number; processing: number; pending: number; error: number; unknown: number } = {
        completed: 0, processing: 0, pending: 0, error: 0, unknown: 0
    };

    allAnalyses.forEach(analysisFile => {
      const status = ((analysisFile as any).status || 'unknown').toLowerCase(); 
      switch (status) {
        case 'completed':
          counts.completed++;
          break;
        case 'processing':
          counts.processing++;
          break;
        case 'pending':
          counts.pending++;
          break;
        case 'error':
          counts.error++;
          break;
        default:
          counts.unknown++;
          break;
      }
    });
    return counts;
  } catch (error) {
    console.error("Error in getStatusCounts:", error);
    return { completed: 0, processing: 0, pending: 0, error: 0, unknown: 0 };
  }
}
// --- TAMBAHKAN FUNGSI INI ---
export async function getPcapAnalysesForUser(userId: string): Promise<PcapAnalysisRecord[]> {
  if (!userId) {
    console.error("getPcapAnalysesForUser: userId is required.");
    return [];
  }
  try {
    console.log(`[ACTIONS] Fetching PCAP analyses for user ID: ${userId}`);
    const pcapFilesFromDb = await db.pcapFile.findMany({ userId: userId });
    
    if (!pcapFilesFromDb) {
        console.warn(`[ACTIONS] No PCAP files found in DB for user ID: ${userId}`);
        return [];
    }
    console.log(`[ACTIONS] Found ${pcapFilesFromDb.length} PCAP files in DB for user ID: ${userId}`);

    return pcapFilesFromDb.map(file => {
      // Pastikan mapping sesuai dengan definisi PcapAnalysisRecord dan data dari db.pcapFile.findMany
      // Terutama createdAt, pastikan itu adalah objek Date atau string ISO yang bisa di-parse menjadi Date.
      // Metode mapPcapFileRow di neon-db.ts sudah mengembalikan createdAt sebagai Date.
      return {
        analysisId: file.analysisId,
        originalName: file.originalName,
        createdAt: new Date(file.createdAt), // Jika createdAt sudah Date, new Date() tidak apa-apa
        status: (file as any).status || 'COMPLETED', // Sesuaikan dengan field status Anda
        size: file.size,
        userId: file.userId,
        fileName: file.fileName,
        blobUrl: file.blobUrl,
      };
    });
  } catch (error) {
    console.error(`[ACTIONS] Error fetching PCAP analyses for user ${userId}:`, error);
    // throw new Error("Failed to fetch PCAP analyses."); // Atau kembalikan array kosong untuk graceful degradation
    return [];
  }
}
// --- SELESAI PENAMBAHAN ---
