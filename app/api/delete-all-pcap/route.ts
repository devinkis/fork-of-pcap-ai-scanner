// app/api/delete-all-pcap/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import db from "@/lib/neon-db";
import { del as deleteBlob } from "@vercel/blob";

export async function DELETE(request: NextRequest) {
  try {
    const user = await getCurrentUser();
    if (!user || !user.id) { // Pastikan user dan user.id ada
      return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    }

    console.log(`[API_DELETE_ALL_PCAP] User ${user.id} attempting to delete all their PCAP analyses.`);

    // 1. Ambil semua record PCAP milik pengguna untuk mendapatkan blobUrls
    const pcapRecords = await db.pcapFile.findMany({ userId: user.id });

    if (!pcapRecords || pcapRecords.length === 0) {
      return NextResponse.json({ success: true, message: "No PCAP analyses found to delete for this user." });
    }

    // 2. Hapus setiap berkas dari Vercel Blob storage
    const blobDeletionPromises = pcapRecords.map(async (record) => {
      if (record.blobUrl) {
        try {
          console.log(`[API_DELETE_ALL_PCAP] Deleting blob: ${record.blobUrl} for user ${user.id}`);
          await deleteBlob(record.blobUrl);
          console.log(`[API_DELETE_ALL_PCAP] Blob ${record.blobUrl} deleted successfully.`);
          return { url: record.blobUrl, status: "deleted" };
        } catch (blobError: any) {
          console.error(`[API_DELETE_ALL_PCAP] Failed to delete blob ${record.blobUrl}:`, blobError);
          return { url: record.blobUrl, status: "error", error: blobError.message };
        }
      }
      return { url: record.blobUrl, status: "skipped_no_url" };
    });

    const blobDeletionResults = await Promise.allSettled(blobDeletionPromises);
    
    // Log hasil penghapusan blob (opsional, untuk debugging)
    blobDeletionResults.forEach(result => {
        if (result.status === 'fulfilled') {
            console.log(`Blob deletion result for ${result.value.url}: ${result.value.status}`, result.value.error ? `Error: ${result.value.error}`: "");
        } else {
            console.error(`Promise rejected for blob deletion:`, result.reason);
        }
    });


    // 3. Hapus semua record dari database milik pengguna tersebut
    // Kita akan menggunakan metode baru deleteManyByUserId
    const dbDeletionResult = await db.pcapFile.deleteManyByUserId({ where: { userId: user.id } });
    const deletedDbCount = dbDeletionResult.count;

    console.log(`[API_DELETE_ALL_PCAP] ${deletedDbCount} database records deleted for user ID ${user.id}.`);

    return NextResponse.json({
      success: true,
      message: `Successfully deleted ${deletedDbCount} PCAP analysis records and associated files.`,
      deletedCount: deletedDbCount,
      blobDeletionResults: blobDeletionResults.map(r => r.status === 'fulfilled' ? r.value : { status: 'error', reason: r.reason}) // Kirim hasil ringkas ke client
    });

  } catch (error: any) {
    console.error("[API_DELETE_ALL_PCAP] Error deleting all PCAP analyses for user:", error);
    return NextResponse.json(
      { error: "Failed to delete all PCAP analyses.", details: error.message },
      { status: 500 }
    );
  }
}
