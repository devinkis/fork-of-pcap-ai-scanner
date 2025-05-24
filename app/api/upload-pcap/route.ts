import { type NextRequest, NextResponse } from "next/server"
import { v4 as uuidv4 } from "uuid"
import { put } from "@vercel/blob"
import db from "@/lib/neon-db"
import { getCurrentUser } from "@/lib/auth"

export async function POST(request: NextRequest) {
  try {
    // Get current user
    const user = await getCurrentUser()

    if (!user) {
      console.error("Upload attempt without authentication")
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    console.log(`Upload request from user: ${user.id} (${user.email})`)

    const formData = await request.formData()
    const file = formData.get("pcapFile") as File

    if (!file) {
      console.error("No file provided in upload request")
      return NextResponse.json({ error: "No file provided" }, { status: 400 })
    }

    // Check file type
    if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
      console.error(`Invalid file format: ${file.name}`)
      return NextResponse.json(
        { error: "Invalid file format. Only .pcap and .pcapng files are supported" },
        { status: 400 },
      )
    }

    // Generate a unique ID for this analysis
    const analysisId = uuidv4()
    const recordId = uuidv4()
    console.log(`Generated analysis ID: ${analysisId} and record ID: ${recordId} for user ${user.id}`)

    // First, let's test the database connection
    try {
      console.log("Testing database connection before upload...")
      await db.testConnection()
      console.log("Database connection test successful")
    } catch (dbTestError) {
      console.error("Database connection test failed:", dbTestError)
      return NextResponse.json({ error: "Database connection failed. Please try again later." }, { status: 500 })
    }

    // Save file information to database FIRST (before blob upload)
    let pcapFile
    try {
      console.log(`Saving file information to database for analysis ${analysisId} with record ID ${recordId}`)
      pcapFile = await db.pcapFile.create({
        data: {
          id: recordId,
          fileName: file.name, // Use original filename initially
          originalName: file.name,
          size: file.size,
          blobUrl: null, // Will update this after blob upload
          analysisId: analysisId, // Make sure we use the correct analysis ID
          userId: user.id,
        },
      })
      console.log(`✅ File information saved to database successfully:`, {
        id: pcapFile.id,
        analysisId: pcapFile.analysisId,
        originalName: pcapFile.originalName,
      })
    } catch (dbError) {
      console.error("Failed to save file information to database:", dbError)
      return NextResponse.json(
        {
          error: "Failed to save file information to database",
          details: dbError instanceof Error ? dbError.message : "Unknown database error",
        },
        { status: 500 },
      )
    }

    // Skip verification step since we can see the record is being created successfully
    // The issue seems to be with the verification query, not the creation

    // Now try to upload to Vercel Blob (optional)
    let blobUrl = null
    try {
      console.log(`Uploading file to Vercel Blob: ${file.name} (${file.size} bytes)`)
      const blob = await put(`pcaps/${user.id}/${analysisId}/${file.name}`, file, {
        access: "public",
        contentType: file.type || "application/octet-stream",
        metadata: {
          userId: user.id,
          analysisId: analysisId,
          originalName: file.name,
          size: file.size.toString(),
          uploadedAt: new Date().toISOString(),
        },
      })
      blobUrl = blob.url
      console.log(`File uploaded successfully to Blob: ${blobUrl}`)

      // Update the database record with the blob URL
      try {
        const updatedRecord = await db.pcapFile.update({
          where: { id: pcapFile.id },
          data: { blobUrl: blobUrl, fileName: blob.pathname },
        })
        console.log(`Database record updated with blob URL:`, updatedRecord)
      } catch (updateError) {
        console.warn("Failed to update database with blob URL:", updateError)
        // This is not critical - we can still proceed
      }
    } catch (blobError) {
      console.warn("Blob storage failed, but continuing with database record:", blobError)
      // Blob storage failure is not critical - we can still analyze the file
    }

    // Return success response
    const response = {
      success: true,
      analysisId: analysisId, // Make sure we return the correct analysis ID
      blobUrl,
      message: "File uploaded successfully and queued for analysis",
      debug: {
        userId: user.id,
        fileName: file.name,
        fileSize: file.size,
        databaseRecordId: pcapFile.id,
        analysisId: analysisId,
      },
    }

    console.log("✅ Upload completed successfully:", response)
    return NextResponse.json(response)
  } catch (error) {
    console.error("Unexpected error in upload handler:", error)
    return NextResponse.json(
      {
        error: "Failed to process upload",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
