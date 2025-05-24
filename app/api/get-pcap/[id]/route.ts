// Path: devinkis/fork-of-pcap-ai-scanner/fork-of-pcap-ai-scanner-fb3444031e0b44895e9fddc8cf7c92cce4812117/app/api/get-pcap/[id]/route.ts
import { type NextRequest, NextResponse } from "next/server"
import { list } from "@vercel/blob"
import db from "@/lib/neon-db"
import { getCurrentUser } from "@/lib/auth"

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    // Get current user
    const user = await getCurrentUser()

    if (!user) {
      console.log("DEBUG: GET /api/get-pcap - Authentication required, user is null."); // Added debug log
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    const analysisId = params.id;

    if (!analysisId) {
      console.log("DEBUG: GET /api/get-pcap - Analysis ID is missing."); // Added debug log
      return NextResponse.json({ error: "Analysis ID is required" }, { status: 400 })
    }

    // --- ADDED DEBUG LOGS HERE ---
    console.log(`DEBUG: Attempting to find PCAP file for analysisId: '${analysisId}' and userId: '${user.id}'`);
    // --- END ADDED DEBUG LOGS ---

    // Check if this analysis belongs to the current user
    const pcapFile = await db.pcapFile.findFirst({
      where: {
        analysisId,
        userId: user.id,
      },
    })

    if (!pcapFile) {
      console.log(`DEBUG: PCAP file not found or permission denied for analysisId: '${analysisId}' and userId: '${user.id}'`); // Added debug log
      return NextResponse.json(
        {
          success: false,
          error: "Analysis not found or you don't have permission to access it",
        },
        { status: 404 },
      )
    }

    // List all blobs in the analysis directory
    const { blobs } = await list({
      prefix: `pcaps/${user.id}/${analysisId}/`,
    })

    if (blobs.length === 0) {
      // Return a successful response with empty files array
      return NextResponse.json({
        success: true,
        files: [],
        message: "No PCAP files found for this analysis",
      })
    }

    // Ensure each blob has the required metadata structure
    const safeBlobs = blobs.map((blob) => ({
      url: blob.url,
      pathname: blob.pathname,
      size: blob.size,
      uploadedAt: blob.uploadedAt,
      metadata: {
        userId: blob.metadata?.userId || user.id,
        analysisId: blob.metadata?.analysisId || analysisId,
        originalName: blob.metadata?.originalName || "unknown.pcap",
        size: blob.metadata?.size || String(blob.size),
        uploadedAt: blob.metadata?.uploadedAt || blob.uploadedAt,
      },
    }))

    // Return information about the PCAP files
    return NextResponse.json({
      success: true,
      files: safeBlobs,
    })
  } catch (error) {
    console.error("Error retrieving PCAP files:", error)

    // Return a structured error response
    return NextResponse.json({
      success: false,
      files: [],
      error: "Failed to retrieve PCAP files",
    })
  }
}
