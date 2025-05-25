// components/pcap-uploader.tsx
"use client";

import type React from "react";
import { useState, useCallback } from "react";
// --- PERBAIKAN MULAI ---
import { UploadCloud, FileUp, Loader2, AlertTriangle, CheckCircle, Zap } from "lucide-react"; 
// --- PERBAIKAN SELESAI ---
import { Button } from "@/components/ui/button"; 
import { Progress } from "@/components/ui/progress"; 
import { useRouter } from "next/navigation";
import { useDropzone } from 'react-dropzone'; 
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"; 
// Impor Card, CardContent, dan Badge
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";


export function PcapUploader() {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const router = useRouter();

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles && acceptedFiles[0]) {
      const currentFile = acceptedFiles[0];
      if (currentFile.name.endsWith(".pcap") || currentFile.name.endsWith(".pcapng")) {
        if (currentFile.size <= 50 * 1024 * 1024) { // Batas 50MB
            setFile(currentFile);
            setError(null);
            setSuccessMessage(null);
        } else {
            setError("File size exceeds 50MB limit.");
            setFile(null);
        }
      } else {
        setError("Invalid file type. Only .pcap and .pcapng are supported.");
        setFile(null);
      }
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: {
        'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng'],
        'application/octet-stream': ['.pcap', '.pcapng'] 
    },
    multiple: false,
    maxSize: 50 * 1024 * 1024, // 50MB
  });

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setUploadProgress(0);
    setError(null);
    setSuccessMessage(null);

    const progressInterval = setInterval(() => {
      setUploadProgress((prev) => (prev >= 95 ? prev : prev + 5));
    }, 200);

    try {
      const formData = new FormData();
      formData.append("pcapFile", file);
      console.log(`Uploading file: ${file.name} (${file.size} bytes)`);

      const response = await fetch("/api/upload-pcap", { 
        method: "POST",
        body: formData,
      });

      clearInterval(progressInterval); 
      const data = await response.json();

      if (!response.ok) {
        console.error("Upload failed with status:", response.status, data);
        throw new Error(data.error || `Upload failed with status: ${response.status}`);
      }
      
      console.log("Upload successful, received data:", data);

      // --- PERBAIKAN MULAI: Validasi data.analysisId ---
      if (data && data.analysisId) {
        setUploadProgress(100);
        setSuccessMessage("Upload successful! Redirecting to analysis...");

        setTimeout(() => {
          try {
            console.log(`Navigating to analysis page: /analysis/${data.analysisId}`);
            router.push(`/analysis/${data.analysisId}`);
          } catch (navigationError) {
            console.error("Navigation error:", navigationError);
            setError("Navigation to analysis page failed. Please check your analyses history.");
            setUploading(false); 
          }
        }, 1500);
      } else {
        console.error("Upload succeeded but analysisId not found in response:", data);
        throw new Error("Upload succeeded, but could not retrieve analysis ID for redirection.");
      }
      // --- PERBAIKAN SELESAI ---
    } catch (uploadError) {
      clearInterval(progressInterval);
      console.error("Error uploading file:", uploadError);
      setUploadProgress(0); // Reset progress jika error
      setUploading(false);
      setError(uploadError instanceof Error ? uploadError.message : "Failed to upload PCAP file");
    }
  };

  return (
    <div className="space-y-6">
      <div
        {...getRootProps()}
        className={`border-2 border-dashed rounded-lg p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-colors duration-200 ease-in-out
                    ${isDragActive ? 'border-primary bg-primary/10' : 'border-gray-300 dark:border-gray-700 hover:border-primary/70'}
                    ${isDragReject ? 'border-red-500 bg-red-500/10' : ''}`}
      >
        <input {...getInputProps()} id="pcap-file-dropzone" />
        <UploadCloud className={`h-12 w-12 mb-4 ${isDragActive ? 'text-primary' : 'text-muted-foreground'}`} />
        {isDragActive ? (
          <p className="text-lg font-semibold text-primary">Drop the file here ...</p>
        ) : (
          <>
            <p className="text-lg font-semibold">Drag & drop or click to upload</p>
            <p className="text-sm text-muted-foreground mt-1">Supports .pcap and .pcapng files (Max 50MB)</p>
          </>
        )}
      </div>

      {error && (
        <Alert variant="destructive" className="mt-4">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Upload Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      
      {successMessage && !error && (
        <Alert variant="default" className="mt-4 bg-green-50 border-green-200 dark:bg-green-900/30 dark:border-green-700">
          <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-400" />
          <AlertTitle className="text-green-700 dark:text-green-300">Success</AlertTitle>
          <AlertDescription className="text-green-600 dark:text-green-400">{successMessage}</AlertDescription>
        </Alert>
      )}

      {file && !successMessage && (
        <Card className="mt-6 shadow-md border dark:border-slate-700">
          <CardContent className="p-4 space-y-3">
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2 min-w-0">
                <FileUp className="h-5 w-5 text-primary flex-shrink-0" />
                <span className="font-medium truncate" title={file.name}>{file.name}</span>
              </div>
              <Badge variant="outline" className="text-xs">{(file.size / (1024 * 1024)).toFixed(2)} MB</Badge>
            </div>

            {uploading && (
              <div className="space-y-1">
                <Progress value={uploadProgress} className="h-2 [&>div]:bg-primary" />
                <p className="text-xs text-muted-foreground text-right">{uploadProgress}%</p>
              </div>
            )}

            <Button onClick={handleUpload} disabled={uploading || !!successMessage} className="w-full bg-primary hover:bg-primary/90 text-primary-foreground">
              {uploading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  {/* --- PERBAIKAN MULAI: Menggunakan ikon Zap --- */}
                  <Zap className="mr-2 h-4 w-4" /> 
                  {/* --- PERBAIKAN SELESAI --- */}
                  Start AI Analysis
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
