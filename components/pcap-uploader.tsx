"use client"

import type React from "react"

import { useState } from "react"
import { Upload, FileUp, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { useRouter } from "next/navigation"

export function PcapUploader() {
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const router = useRouter()

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setError(null)
    }
  }

  const handleUpload = async () => {
    if (!file) return

    setUploading(true)
    setUploadProgress(0)
    setError(null)

    // Simulate upload progress
    const progressInterval = setInterval(() => {
      setUploadProgress((prev) => {
        if (prev >= 95) {
          clearInterval(progressInterval)
          return prev
        }
        return prev + 5
      })
    }, 200)

    try {
      // Create FormData
      const formData = new FormData()
      formData.append("pcapFile", file)

      console.log(`Uploading file: ${file.name} (${file.size} bytes)`)

      // Send to API route
      const response = await fetch("/api/upload-pcap", {
        method: "POST",
        body: formData,
      })

      if (!response.ok) {
        const errorData = await response.json()
        console.error("Upload failed with status:", response.status, errorData)
        throw new Error(errorData.error || `Upload failed with status: ${response.status}`)
      }

      const data = await response.json()
      console.log("Upload successful, received data:", data)

      // Complete progress bar
      clearInterval(progressInterval)
      setUploadProgress(100)

      // Navigate to analysis page with a slight delay to ensure UI updates
      setTimeout(() => {
        try {
          console.log(`Navigating to analysis page: /analysis/${data.analysisId}`)
          router.push(`/analysis/${data.analysisId}`)
        } catch (error) {
          console.error("Navigation error:", error)
          setError("There was an error navigating to the analysis page. Please try again.")
        }
      }, 1000)
    } catch (error) {
      clearInterval(progressInterval)
      console.error("Error uploading file:", error)
      setUploadProgress(0)
      setUploading(false)
      setError(error instanceof Error ? error.message : "Failed to upload PCAP file")
    }
  }

  return (
    <div className="space-y-4">
      <div
        className="border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center cursor-pointer hover:bg-muted/50 transition-colors"
        onClick={() => document.getElementById("pcap-file")?.click()}
      >
        <input type="file" id="pcap-file" accept=".pcap,.pcapng" className="hidden" onChange={handleFileChange} />
        <Upload className="h-10 w-10 text-muted-foreground mb-2" />
        <p className="text-sm text-muted-foreground mb-1">{file ? file.name : "Click to upload or drag and drop"}</p>
        <p className="text-xs text-muted-foreground">Supports .pcap and .pcapng files</p>
      </div>

      {file && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <FileUp className="h-4 w-4 mr-2 text-muted-foreground" />
              <span className="text-sm font-medium truncate max-w-[200px]">{file.name}</span>
            </div>
            <span className="text-xs text-muted-foreground">{(file.size / (1024 * 1024)).toFixed(2)} MB</span>
          </div>

          {uploading && <Progress value={uploadProgress} className="h-2" />}

          {error && <p className="text-sm text-red-500">{error}</p>}

          <Button onClick={handleUpload} disabled={uploading} className="w-full">
            {uploading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Uploading...
              </>
            ) : (
              "Analyze with AI"
            )}
          </Button>
        </div>
      )}
    </div>
  )
}
