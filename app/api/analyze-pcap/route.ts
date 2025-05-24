import { type NextRequest, NextResponse } from "next/server"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"
import { list } from "@vercel/blob"

export async function POST(request: NextRequest) {
  try {
    const { analysisId } = await request.json()

    if (!analysisId) {
      return NextResponse.json({ error: "No analysis ID provided" }, { status: 400 })
    }

    // Get the PCAP file from Vercel Blob
    const { blobs } = await list({
      prefix: `pcaps/${analysisId}/`,
    })

    if (blobs.length === 0) {
      return NextResponse.json({ error: "No PCAP file found for this analysis" }, { status: 404 })
    }

    const pcapFile = blobs[0]

    // In a real application, you would parse the PCAP file and extract packet data
    // For this example, we'll use mock packet data
    const mockPacketData = {
      analysisId,
      fileName: pcapFile.metadata.originalName,
      fileSize: pcapFile.size,
      uploadedAt: pcapFile.uploadedAt,
      packets: [
        {
          timestamp: new Date().toISOString(),
          sourceIp: "192.168.1.105",
          destIp: "203.0.113.42",
          protocol: "TCP",
          length: 1420,
          info: "PSH ACK",
        },
        {
          timestamp: new Date().toISOString(),
          sourceIp: "192.168.1.105",
          destIp: "8.8.8.8",
          protocol: "DNS",
          length: 64,
          info: "A? suspicious-domain.com",
        },
        // Add more mock packets as needed
      ],
      statistics: {
        totalPackets: 1245,
        protocols: {
          TCP: 823,
          UDP: 312,
          HTTP: 56,
          DNS: 42,
          HTTPS: 12,
        },
        topSources: ["192.168.1.105", "192.168.1.1", "10.0.0.2"],
        topDestinations: ["203.0.113.42", "8.8.8.8", "192.168.1.1"],
      },
    }

    // Use AI to analyze the packet data
    const { text: analysis } = await generateText({
      model: openai("gpt-4o"),
      prompt: `
        You are a network security expert analyzing PCAP data. 
        Analyze the following network packet data and identify any potential security threats, 
        unusual patterns, or anomalies. Provide a detailed analysis with specific findings and recommendations.
        
        Also extract any potential indicators of compromise (IOCs) such as suspicious IP addresses, domains, URLs, or file hashes.
        
        Packet data:
        ${JSON.stringify(mockPacketData, null, 2)}
        
        Format your response as JSON with the following structure:
        {
          "summary": "Brief overview of findings",
          "threatLevel": "low|medium|high|critical",
          "findings": [
            {
              "title": "Finding title",
              "description": "Detailed description",
              "severity": "low|medium|high|critical",
              "confidence": 0-100,
              "recommendation": "Recommended action"
            }
          ],
          "iocs": [
            {
              "type": "ip|domain|url|hash",
              "value": "The actual IOC value",
              "context": "Where this IOC was found",
              "confidence": 0-100
            }
          ]
        }
      `,
    })

    // Parse the AI response
    const aiAnalysis = JSON.parse(analysis)

    return NextResponse.json({
      success: true,
      analysis: aiAnalysis,
    })
  } catch (error) {
    console.error("Error analyzing packet data:", error)
    return NextResponse.json({ error: "Failed to analyze packet data" }, { status: 500 })
  }
}
