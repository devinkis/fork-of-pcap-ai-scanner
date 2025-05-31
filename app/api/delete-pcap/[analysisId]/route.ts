// app/api/delete-pcap/[analysisId]/route.ts
import { type NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import db from "@/lib/neon-db";
import { del as deleteBlob } from "@vercel/blob";

export const runtime = 'nodejs';
export async function DELETE(
  request: NextRequest,
  { params }: { params: { analysisId: string } }
) {
  try {
    const user = await getCurrentUser();
    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    }

    const analysisIdToDelete = params.analysisId;
    if (!analysisIdToDelete) {
      return NextResponse.json({ error: "Analysis ID is required" }, { status: 400 });
    }

    console.log(`[API_DELETE_PCAP] User ${user.id} attempting to delete analysis: ${analysisIdToDelete}`);

    const pcapRecord = await db.pcapFile.findFirst({
      where: {
        analysisId: analysisIdToDelete,
        userId: user.id, 
      },
    });

    if (!pcapRecord) {
      return NextResponse.json(
        { error: "PCAP analysis not found or you do not have permission to delete it." },
        { status: 404 }
      );
    }

    if (pcapRecord.blobUrl) {
      try {
        console.log(`[API_DELETE_PCAP] Deleting blob: ${pcapRecord.blobUrl}`);
        await deleteBlob(pcapRecord.blobUrl);
        console.log(`[API_DELETE_PCAP] Blob ${pcapRecord.blobUrl} deleted successfully.`);
      } catch (blobError: any) {
        console.error(`[API_DELETE_PCAP] Failed to delete blob ${pcapRecord.blobUrl}:`, blobError);
        // Lanjutkan penghapusan record DB meskipun blob gagal dihapus, tapi log errornya
      }
    } else {
        console.warn(`[API_DELETE_PCAP] No blobUrl found for analysisId: ${analysisIdToDelete}. Skipping blob deletion.`);
    }

    // pcapRecord.id adalah ID unik dari baris di tabel pcap_files
    // Pastikan findFirst mengembalikan field 'id' dari tabel pcap_files
    // Jika findFirst di neon-db.ts mengembalikan object dengan id, maka pcapRecord.id akan ada.
    if (!pcapRecord.id) { // Pemeriksaan tambahan
        console.error(`[API_DELETE_PCAP] Record ID not found for analysisId: ${analysisIdToDelete}. Cannot delete from DB.`);
        return NextResponse.json({ error: "Database record ID missing, cannot delete." }, { status: 500 });
    }
    await db.pcapFile.delete({ where: { id: pcapRecord.id } }); 
    console.log(`[API_DELETE_PCAP] Database record for analysisId ${analysisIdToDelete} (DB ID: ${pcapRecord.id}) deleted successfully.`);

    return NextResponse.json({ success: true, message: "PCAP analysis and associated file deleted successfully." });

  } catch (error: any) {
    console.error("[API_DELETE_PCAP] Error deleting PCAP analysis:", error);
    return NextResponse.json(
      { error: "Failed to delete PCAP analysis.", details: error.message },
      { status: 500 }
    );
  }
}
