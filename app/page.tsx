import { PcapUploader } from "@/components/pcap-uploader"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { requireAuth } from "@/lib/auth"

export default async function Home() {
  // Require authentication to access the main page
  await requireAuth()

  return (
    <main className="container mx-auto py-10 px-4">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold mb-4">PCAP Scanner with AI</h1>
        <p className="text-xl text-muted-foreground">
          Upload and analyze network packet captures with advanced AI insights
        </p>
      </div>

      <div className="max-w-2xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle>Upload PCAP File</CardTitle>
            <CardDescription>
              Select a .pcap or .pcapng file to analyze network traffic patterns and security insights
            </CardDescription>
          </CardHeader>
          <CardContent>
            <PcapUploader />
          </CardContent>
        </Card>
      </div>
    </main>
  )
}
