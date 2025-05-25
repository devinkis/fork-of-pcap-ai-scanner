// app/page.tsx
import { PcapUploader } from "@/components/pcap-uploader"; //
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"; //
import { requireAuth } from "@/lib/auth"; //
import { FileUp, ShieldCheck, Zap } from "lucide-react"; // Tambahkan ikon

export default async function Home() {
  await requireAuth();

  return (
    <main className="flex-1 bg-gradient-to-br from-slate-50 via-gray-100 to-slate-200 dark:from-slate-900 dark:via-slate-800 dark:to-gray-900">
      <div className="container mx-auto py-12 px-4 md:px-6 lg:py-20">
        <div className="mx-auto max-w-3xl text-center">
          <ShieldCheck className="mx-auto h-16 w-16 text-primary mb-6" />
          <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl mb-6 bg-clip-text text-transparent bg-gradient-to-r from-slate-900 to-slate-600 dark:from-slate-200 dark:to-slate-400">
            Advanced PCAP Analysis
          </h1>
          <p className="text-lg text-muted-foreground lg:text-xl mb-10">
            Securely upload your network packet captures (.pcap, .pcapng) and get
            AI-powered insights, detailed packet breakdowns, and visual network graphs.
          </p>
        </div>

        <div className="mx-auto max-w-xl">
          <Card className="shadow-2xl rounded-xl border-t-4 border-primary dark:border-primary-foreground/50">
            <CardHeader className="text-center pb-4">
              <div className="inline-flex items-center justify-center bg-primary text-primary-foreground rounded-full p-3 mb-4 mx-auto">
                <FileUp className="h-8 w-8" />
              </div>
              <CardTitle className="text-2xl font-semibold">Upload Your PCAP File</CardTitle>
              <CardDescription className="text-base">
                Drag & drop or click to select a file. Max 50MB.
              </CardDescription>
            </CardHeader>
            <CardContent className="px-6 pb-6">
              <PcapUploader />
            </CardContent>
          </Card>
        </div>

        <section className="mt-20 lg:mt-28">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
            <div className="space-y-3">
              <Zap className="mx-auto h-10 w-10 text-primary" />
              <h3 className="text-xl font-semibold">Rapid AI Insights</h3>
              <p className="text-muted-foreground">
                Leverage cutting-edge AI to quickly identify potential threats,
                anomalies, and misconfigurations.
              </p>
            </div>
            <div className="space-y-3">
              <ListChecks className="mx-auto h-10 w-10 text-primary" />
              <h3 className="text-xl font-semibold">Detailed Packet View</h3>
              <p className="text-muted-foreground">
                Inspect individual packets with detailed header information and
                hexadecimal dumps.
              </p>
            </div>
            <div className="space-y-3">
              <Network className="mx-auto h-10 w-10 text-primary" />
              <h3 className="text-xl font-semibold">Network Visualization</h3>
              <p className="text-muted-foreground">
                Understand communication patterns and relationships with an
                interactive network graph.
              </p>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
