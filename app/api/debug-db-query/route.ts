// /api/debug-db-query/route.ts
import { NextResponse } from "next/server";
import db from "@/lib/neon-db"; // Assuming this still works
import { getCurrentUser } from "@/lib/auth";

export async function GET() {
  try {
    const user = await getCurrentUser();
    if (!user) {
      return NextResponse.json({ error: "Auth needed" }, { status: 401 });
    }

    const hardcodedAnalysisId = "YOUR_EXISTING_ANALYSIS_ID_FROM_DB"; // Replace with a real analysis ID
    const hardcodedUserId = user.id; // Use the authenticated user's ID

    console.log(`DEBUG_TEST: Calling findFirst with hardcoded values: analysisId=<span class="math-inline">\{hardcodedAnalysisId\}, userId\=</span>{hardcodedUserId}`);

    const pcapFile = await db.pcapFile.findFirst({
      where: {
        analysisId: hardcodedAnalysisId,
        userId: hardcodedUserId,
      },
    });

    if (pcapFile) {
      console.log("DEBUG_TEST: Found PCAP file:", pcapFile.originalName);
      return NextResponse.json({ success: true, message: "PCAP file found in debug query", pcapFile });
    } else {
      console.log("DEBUG_TEST: PCAP file NOT found in debug query.");
      return NextResponse.json({ success: false, message: "PCAP file not found in debug query" });
    }
  } catch (error) {
    console.error("DEBUG_TEST: Error in debug query:", error);
    return NextResponse.json({ success: false, message: "Error during debug query", details: error.message }, { status: 500 });
  }
}
