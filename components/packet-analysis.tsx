"use client"

import { useState, useEffect, useRef } from "react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Loader2, FileDown, AlertTriangle, X, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"

interface Packet {
  id: number
  timestamp: string
  sourceIp: string
  sourcePort: number
  destIp: string
  destPort: number
  protocol: string
  length: number
  info: string
  flags?: string[]
  tcpSeq?: number
  tcpAck?: number
  windowSize?: number
  ttl?: number
  isError?: boolean
  errorType?: string
  hexDump?: string[]
  rawData?: string
  detailedInfo?: {
    [key: string]: any
  }
}

interface Connection {
  id: string
  sourceIp: string
  sourcePort: number
  destIp: string
  destPort: number
  protocol: string
  state: string
  packets: number[]
  startTime: string
  endTime?: string
  hasErrors: boolean
  errorTypes: string[]
}

interface BlobFile {
  url: string
  pathname: string
  size: number
  uploadedAt: string
  metadata?: {
    analysisId?: string
    originalName?: string
    size?: string
    uploadedAt?: string
  }
}

interface PacketAnalysisProps {
  analysisId: string
}

export function PacketAnalysis({ analysisId }: PacketAnalysisProps) {
  const [packets, setPackets] = useState<Packet[]>([])
  const [connections, setConnections] = useState<Connection[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState("")
  const [pcapFile, setPcapFile] = useState<BlobFile | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null)
  const [showOnlyErrors, setShowOnlyErrors] = useState(false)
  const [filterType, setFilterType] = useState<string>("all")
  const tableRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Fetch the PCAP file information from Vercel Blob
    const fetchPcapFile = async () => {
      try {
        const response = await fetch(`/api/get-pcap/${analysisId}`)

        if (!response.ok) {
          throw new Error("Failed to fetch PCAP file information")
        }

        const data = await response.json()

        if (data.success && data.files.length > 0) {
          setPcapFile(data.files[0])
        }
      } catch (error) {
        console.error("Error fetching PCAP file:", error)
        setError("Failed to fetch PCAP file information")
      }
    }

    // Fetch packet data
    const fetchPackets = async () => {
      try {
        // In a real application, you would parse the PCAP file
        // For demo purposes, we'll use mock data that includes network errors
        await new Promise((resolve) => setTimeout(resolve, 1500))

        // Generate mock packets with network errors and TCP handshake issues
        const mockPackets: Packet[] = generateMockPacketsWithErrors(150)
        setPackets(mockPackets)

        // Generate connections from packets
        const mockConnections = generateConnectionsFromPackets(mockPackets)
        setConnections(mockConnections)
      } catch (error) {
        console.error("Error fetching packet data:", error)
        setError("Failed to fetch packet data")
      } finally {
        setLoading(false)
      }
    }

    fetchPcapFile()
    fetchPackets()
  }, [analysisId])

  // Generate mock packets with network errors and TCP handshake issues
  const generateMockPacketsWithErrors = (count: number): Packet[] => {
    const protocols = ["TCP", "UDP", "HTTP", "DNS", "HTTPS", "ICMP"]
    const errorTypes = [
      "TCP Reset",
      "TCP Reset from Client",
      "Failed Handshake",
      "Connection Timeout",
      "Duplicate ACK",
      "Zero Window",
      "Retransmission",
      "Out of Order",
    ]
    const tcpFlags = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]
    const ips = ["192.168.1.105", "192.168.1.1", "10.0.0.2", "172.16.0.5", "203.0.113.42", "8.8.8.8", "8.8.4.4"]
    const ports = [80, 443, 22, 53, 3389, 8080, 21, 25, 110]

    const packets: Packet[] = []
    const startTime = Date.now() - 3600000 // 1 hour ago

    // Create some normal packets
    for (let i = 0; i < count * 0.7; i++) {
      const protocol = protocols[Math.floor(Math.random() * protocols.length)]
      const sourceIp = ips[Math.floor(Math.random() * ips.length)]
      const destIp = ips[Math.floor(Math.random() * ips.length)]
      const sourcePort = ports[Math.floor(Math.random() * ports.length)]
      const destPort = ports[Math.floor(Math.random() * ports.length)]
      const timestamp = new Date(startTime + i * 1000 + Math.random() * 500).toISOString()
      const length = Math.floor(Math.random() * 1500) + 40
      const ttl = Math.floor(Math.random() * 64) + 1

      let info = ""
      let flags: string[] = []
      let tcpSeq = undefined
      let tcpAck = undefined
      let windowSize = undefined

      if (protocol === "TCP") {
        flags = [tcpFlags[Math.floor(Math.random() * tcpFlags.length)]]
        if (Math.random() > 0.5) {
          flags.push(tcpFlags[Math.floor(Math.random() * tcpFlags.length)])
        }
        tcpSeq = Math.floor(Math.random() * 1000000000)
        tcpAck = Math.floor(Math.random() * 1000000000)
        windowSize = Math.floor(Math.random() * 65535)
        info = flags.join(" ")
      } else if (protocol === "HTTP") {
        info = ["GET /index.html", "POST /api/data", "PUT /api/update", "DELETE /api/resource"][
          Math.floor(Math.random() * 4)
        ]
      } else if (protocol === "DNS") {
        info = ["A? example.com", "AAAA? google.com", "MX? microsoft.com"][Math.floor(Math.random() * 3)]
      } else if (protocol === "ICMP") {
        info = ["Echo request", "Echo reply", "Destination unreachable"][Math.floor(Math.random() * 3)]
      } else {
        info = "Data"
      }

      // Generate hex dump
      const hexDump = generateHexDump(length)

      packets.push({
        id: i + 1,
        timestamp,
        sourceIp,
        sourcePort,
        destIp,
        destPort,
        protocol,
        length,
        info,
        flags,
        tcpSeq,
        tcpAck,
        windowSize,
        ttl,
        isError: false,
        hexDump,
        detailedInfo: generateDetailedInfo(
          protocol,
          sourceIp,
          destIp,
          sourcePort,
          destPort,
          flags,
          tcpSeq,
          tcpAck,
          windowSize,
          ttl,
        ),
      })
    }

    // Create error packets
    for (let i = 0; i < count * 0.3; i++) {
      const errorType = errorTypes[Math.floor(Math.random() * errorTypes.length)]
      const protocol = errorType.includes("TCP") ? "TCP" : protocols[Math.floor(Math.random() * protocols.length)]
      const sourceIp = ips[Math.floor(Math.random() * ips.length)]
      const destIp = ips[Math.floor(Math.random() * ips.length)]
      const sourcePort = ports[Math.floor(Math.random() * ports.length)]
      const destPort = ports[Math.floor(Math.random() * ports.length)]
      const timestamp = new Date(startTime + (count * 0.7 + i) * 1000 + Math.random() * 500).toISOString()
      const length = Math.floor(Math.random() * 1500) + 40
      const ttl = Math.floor(Math.random() * 64) + 1

      let info = errorType
      let flags: string[] = []
      let tcpSeq = undefined
      let tcpAck = undefined
      let windowSize = undefined

      if (protocol === "TCP") {
        if (errorType === "TCP Reset" || errorType === "TCP Reset from Client") {
          flags = ["RST"]
          info = "RST " + errorType
        } else if (errorType === "Failed Handshake") {
          flags = ["SYN"]
          info = "SYN [Failed Handshake]"
        } else if (errorType === "Duplicate ACK") {
          flags = ["ACK"]
          info = "ACK [Duplicate]"
        } else if (errorType === "Zero Window") {
          flags = ["ACK"]
          windowSize = 0
          info = "ACK [Zero Window]"
        } else if (errorType === "Retransmission") {
          flags = ["PSH", "ACK"]
          info = "PSH ACK [Retransmission]"
        } else if (errorType === "Out of Order") {
          flags = ["PSH", "ACK"]
          info = "PSH ACK [Out of Order]"
        }
        tcpSeq = Math.floor(Math.random() * 1000000000)
        tcpAck = Math.floor(Math.random() * 1000000000)
        windowSize = windowSize !== undefined ? windowSize : Math.floor(Math.random() * 65535)
      }

      // Generate hex dump
      const hexDump = generateHexDump(length)

      packets.push({
        id: Math.floor(count * 0.7) + i + 1,
        timestamp,
        sourceIp,
        sourcePort,
        destIp,
        destPort,
        protocol,
        length,
        info,
        flags,
        tcpSeq,
        tcpAck,
        windowSize,
        ttl,
        isError: true,
        errorType,
        hexDump,
        detailedInfo: generateDetailedInfo(
          protocol,
          sourceIp,
          destIp,
          sourcePort,
          destPort,
          flags,
          tcpSeq,
          tcpAck,
          windowSize,
          ttl,
        ),
      })
    }

    // Sort packets by timestamp
    packets.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

    // Reassign IDs
    packets.forEach((packet, index) => {
      packet.id = index + 1
    })

    return packets
  }

  // Generate connections from packets
  const generateConnectionsFromPackets = (packets: Packet[]): Connection[] => {
    const connectionMap = new Map<string, Connection>()

    packets.forEach((packet) => {
      if (packet.protocol === "TCP" || packet.protocol === "UDP") {
        // Create a unique connection ID
        const forwardId = `${packet.sourceIp}:${packet.sourcePort}-${packet.destIp}:${packet.destPort}-${packet.protocol}`
        const reverseId = `${packet.destIp}:${packet.destPort}-${packet.sourceIp}:${packet.sourcePort}-${packet.protocol}`

        // Check if this connection already exists (in either direction)
        const connectionId = connectionMap.has(forwardId)
          ? forwardId
          : connectionMap.has(reverseId)
            ? reverseId
            : forwardId

        if (!connectionMap.has(connectionId)) {
          // Create a new connection
          connectionMap.set(connectionId, {
            id: connectionId,
            sourceIp: packet.sourceIp,
            sourcePort: packet.sourcePort,
            destIp: packet.destIp,
            destPort: packet.destPort,
            protocol: packet.protocol,
            state: packet.protocol === "TCP" ? "ESTABLISHED" : "ACTIVE",
            packets: [],
            startTime: packet.timestamp,
            hasErrors: false,
            errorTypes: [],
          })
        }

        // Add packet to connection
        const connection = connectionMap.get(connectionId)!
        connection.packets.push(packet.id)
        connection.endTime = packet.timestamp

        // Update connection state based on TCP flags
        if (packet.protocol === "TCP" && packet.flags) {
          if (packet.flags.includes("RST")) {
            connection.state = "RESET"
          } else if (packet.flags.includes("FIN")) {
            connection.state = "CLOSED"
          }
        }

        // Update error information
        if (packet.isError) {
          connection.hasErrors = true
          if (packet.errorType && !connection.errorTypes.includes(packet.errorType)) {
            connection.errorTypes.push(packet.errorType)
          }
        }
      }
    })

    return Array.from(connectionMap.values())
  }

  // Generate hex dump for a packet
  const generateHexDump = (length: number): string[] => {
    const lines: string[] = []
    const bytesPerLine = 16
    const numLines = Math.ceil(Math.min(length, 128) / bytesPerLine)

    for (let i = 0; i < numLines; i++) {
      let hexPart = ""
      let asciiPart = ""

      for (let j = 0; j < bytesPerLine; j++) {
        if (i * bytesPerLine + j < length) {
          const byte = Math.floor(Math.random() * 256)
          hexPart += byte.toString(16).padStart(2, "0") + " "
          asciiPart += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : "."
        } else {
          hexPart += "   "
          asciiPart += " "
        }
      }

      lines.push(`${(i * bytesPerLine).toString(16).padStart(4, "0")}  ${hexPart} ${asciiPart}`)
    }

    return lines
  }

  // Generate detailed info for a packet
  const generateDetailedInfo = (
    protocol: string,
    sourceIp: string,
    destIp: string,
    sourcePort: number,
    destPort: number,
    flags?: string[],
    tcpSeq?: number,
    tcpAck?: number,
    windowSize?: number,
    ttl?: number,
  ) => {
    const info: { [key: string]: any } = {
      "Frame Information": {
        "Arrival Time": new Date().toISOString(),
        "Frame Number": Math.floor(Math.random() * 1000) + 1,
        "Frame Length": Math.floor(Math.random() * 1500) + 40,
      },
      "Ethernet II": {
        Destination: "00:11:22:33:44:55",
        Source: "AA:BB:CC:DD:EE:FF",
        Type: "IPv4 (0x0800)",
      },
      "Internet Protocol Version 4": {
        Version: 4,
        "Header Length": 20,
        "Differentiated Services Field": "0x00",
        "Total Length": Math.floor(Math.random() * 1500) + 40,
        Identification:
          "0x" +
          Math.floor(Math.random() * 65535)
            .toString(16)
            .padStart(4, "0"),
        Flags: "0x02",
        "Fragment Offset": 0,
        "Time to Live": ttl || Math.floor(Math.random() * 64) + 1,
        Protocol: protocol === "TCP" ? "TCP (6)" : protocol === "UDP" ? "UDP (17)" : "ICMP (1)",
        "Header Checksum":
          "0x" +
          Math.floor(Math.random() * 65535)
            .toString(16)
            .padStart(4, "0"),
        "Source Address": sourceIp,
        "Destination Address": destIp,
      },
    }

    if (protocol === "TCP") {
      info["Transmission Control Protocol"] = {
        "Source Port": sourcePort,
        "Destination Port": destPort,
        "Sequence Number": tcpSeq || Math.floor(Math.random() * 1000000000),
        "Acknowledgment Number": tcpAck || Math.floor(Math.random() * 1000000000),
        "Header Length": 20,
        Flags: flags?.join(" ") || "ACK",
        "Window Size": windowSize || Math.floor(Math.random() * 65535),
        Checksum:
          "0x" +
          Math.floor(Math.random() * 65535)
            .toString(16)
            .padStart(4, "0"),
        "Urgent Pointer": 0,
      }
    } else if (protocol === "UDP") {
      info["User Datagram Protocol"] = {
        "Source Port": sourcePort,
        "Destination Port": destPort,
        Length: Math.floor(Math.random() * 1000) + 8,
        Checksum:
          "0x" +
          Math.floor(Math.random() * 65535)
            .toString(16)
            .padStart(4, "0"),
      }
    } else if (protocol === "ICMP") {
      info["Internet Control Message Protocol"] = {
        Type: Math.floor(Math.random() * 10),
        Code: Math.floor(Math.random() * 10),
        Checksum:
          "0x" +
          Math.floor(Math.random() * 65535)
            .toString(16)
            .padStart(4, "0"),
        Identifier: Math.floor(Math.random() * 65535),
        "Sequence Number": Math.floor(Math.random() * 65535),
      }
    }

    return info
  }

  const filteredPackets = packets.filter((packet) => {
    // Apply text filter
    const textMatch =
      filter === "" ||
      packet.sourceIp.includes(filter) ||
      packet.destIp.includes(filter) ||
      packet.protocol.toLowerCase().includes(filter.toLowerCase()) ||
      packet.info.toLowerCase().includes(filter.toLowerCase()) ||
      packet.id.toString().includes(filter)

    // Apply error filter
    const errorMatch = !showOnlyErrors || packet.isError

    // Apply type filter
    let typeMatch = true
    if (filterType === "tcp-reset") {
      typeMatch = packet.errorType === "TCP Reset" || packet.errorType === "TCP Reset from Client"
    } else if (filterType === "failed-handshake") {
      typeMatch = packet.errorType === "Failed Handshake"
    } else if (filterType === "connection-issues") {
      typeMatch = packet.isError && !!packet.errorType
    }

    return textMatch && errorMatch && typeMatch
  })

  const getProtocolColor = (protocol: string) => {
    switch (protocol) {
      case "TCP":
        return "bg-blue-100 text-blue-800"
      case "UDP":
        return "bg-green-100 text-green-800"
      case "HTTP":
        return "bg-purple-100 text-purple-800"
      case "HTTPS":
        return "bg-indigo-100 text-indigo-800"
      case "DNS":
        return "bg-yellow-100 text-yellow-800"
      case "ICMP":
        return "bg-orange-100 text-orange-800"
      default:
        return "bg-gray-100 text-gray-800"
    }
  }

  const getRowClassName = (packet: Packet) => {
    if (packet.isError) {
      return "bg-red-50"
    }
    return ""
  }

  const downloadPcapFile = async () => {
    if (!pcapFile) return

    try {
      const response = await fetch(pcapFile.url)

      if (!response.ok) {
        throw new Error("Failed to download file")
      }

      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url

      // Safely access originalName with fallback
      const fileName = pcapFile.metadata?.originalName || "download.pcap"
      a.download = fileName

      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error("Error downloading file:", error)
      setError("Failed to download PCAP file")
    }
  }

  const handlePacketClick = (packet: Packet) => {
    setSelectedPacket(packet)
    // Scroll to the selected packet in the table
    if (tableRef.current) {
      const row = tableRef.current.querySelector(`tr[data-packet-id="${packet.id}"]`)
      if (row) {
        row.scrollIntoView({ behavior: "smooth", block: "center" })
      }
    }
  }

  const applyFilter = (type: string) => {
    setFilterType(type)
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-red-500">Error</CardTitle>
        </CardHeader>
        <CardContent>
          <p>{error}</p>
          <Button onClick={() => window.location.reload()} className="mt-4">
            Try Again
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold">Packet Analysis</h2>
        <div className="flex gap-2">
          {pcapFile && (
            <Button variant="outline" size="sm" onClick={downloadPcapFile}>
              <FileDown className="h-4 w-4 mr-2" />
              Download PCAP
            </Button>
          )}
        </div>
      </div>

      {pcapFile && pcapFile.metadata && (
        <div className="text-sm text-muted-foreground">
          Analyzing file: {pcapFile.metadata.originalName || "Unknown file"} (
          {pcapFile.metadata.size ? (Number.parseInt(pcapFile.metadata.size) / (1024 * 1024)).toFixed(2) : "?"} MB)
        </div>
      )}

      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap gap-2 items-center">
          <div className="flex items-center gap-2">
            <Input
              placeholder="Filter packets..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-64"
            />
            <Button variant="outline" size="sm" onClick={() => setFilter("")} disabled={!filter}>
              <X className="h-4 w-4" />
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <Select value={filterType} onValueChange={applyFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Packets</SelectItem>
                <SelectItem value="tcp-reset">TCP Resets</SelectItem>
                <SelectItem value="failed-handshake">Failed Handshakes</SelectItem>
                <SelectItem value="connection-issues">Connection Issues</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            <Checkbox
              id="show-errors"
              checked={showOnlyErrors}
              onCheckedChange={(checked) => setShowOnlyErrors(checked as boolean)}
            />
            <label
              htmlFor="show-errors"
              className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
            >
              Show only errors
            </label>
          </div>

          <div className="ml-auto">
            <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Packet Summary</CardTitle>
                <CardDescription>
                  Showing {filteredPackets.length} of {packets.length} packets
                  {showOnlyErrors && ` (${packets.filter((p) => p.isError).length} errors)`}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="flex justify-center items-center h-60">
                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                  </div>
                ) : (
                  <div className="rounded-md border overflow-auto max-h-[500px]" ref={tableRef}>
                    <Table>
                      <TableHeader className="sticky top-0 bg-background z-10">
                        <TableRow>
                          <TableHead className="w-12">No.</TableHead>
                          <TableHead>Time</TableHead>
                          <TableHead>Source</TableHead>
                          <TableHead>Destination</TableHead>
                          <TableHead>Protocol</TableHead>
                          <TableHead>Length</TableHead>
                          <TableHead>Info</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredPackets.map((packet) => (
                          <TableRow
                            key={packet.id}
                            className={`${getRowClassName(packet)} ${
                              selectedPacket?.id === packet.id ? "bg-muted" : ""
                            } cursor-pointer hover:bg-muted/50`}
                            onClick={() => handlePacketClick(packet)}
                            data-packet-id={packet.id}
                          >
                            <TableCell className="font-medium">
                              {packet.isError && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                              {packet.id}
                            </TableCell>
                            <TableCell>{new Date(packet.timestamp).toLocaleTimeString()}</TableCell>
                            <TableCell>{`${packet.sourceIp}:${packet.sourcePort}`}</TableCell>
                            <TableCell>{`${packet.destIp}:${packet.destPort}`}</TableCell>
                            <TableCell>
                              <Badge className={getProtocolColor(packet.protocol)}>{packet.protocol}</Badge>
                            </TableCell>
                            <TableCell>{packet.length} bytes</TableCell>
                            <TableCell
                              className={`max-w-xs truncate ${packet.isError ? "text-red-600 font-medium" : ""}`}
                            >
                              {packet.info}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <div>
            {selectedPacket ? (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="flex justify-between items-center">
                    <span>Packet Details</span>
                    <span className="text-sm font-normal">#{selectedPacket.id}</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <Tabs defaultValue="details">
                    <TabsList className="w-full justify-start rounded-none border-b bg-transparent p-0">
                      <TabsTrigger
                        value="details"
                        className="rounded-none border-b-2 border-transparent px-4 py-2 data-[state=active]:border-primary"
                      >
                        Details
                      </TabsTrigger>
                      <TabsTrigger
                        value="hex"
                        className="rounded-none border-b-2 border-transparent px-4 py-2 data-[state=active]:border-primary"
                      >
                        Hex View
                      </TabsTrigger>
                    </TabsList>
                    <TabsContent value="details" className="p-4">
                      <Accordion type="multiple" defaultValue={["frame", "ip", "protocol"]}>
                        {selectedPacket.detailedInfo &&
                          Object.entries(selectedPacket.detailedInfo).map(([section, details], index) => (
                            <AccordionItem key={index} value={section.toLowerCase().replace(/\s+/g, "-")}>
                              <AccordionTrigger className="py-2">{section}</AccordionTrigger>
                              <AccordionContent>
                                <div className="space-y-1 text-sm">
                                  {Object.entries(details).map(([key, value], i) => (
                                    <div key={i} className="grid grid-cols-2 gap-2">
                                      <div className="font-medium">{key}:</div>
                                      <div>{value}</div>
                                    </div>
                                  ))}
                                </div>
                              </AccordionContent>
                            </AccordionItem>
                          ))}
                      </Accordion>

                      {selectedPacket.isError && (
                        <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
                          <h4 className="text-red-600 font-medium flex items-center">
                            <AlertTriangle className="h-4 w-4 mr-2" />
                            Error: {selectedPacket.errorType}
                          </h4>
                          <p className="mt-1 text-sm text-red-600">
                            {selectedPacket.errorType === "TCP Reset"
                              ? "The connection was forcibly closed by sending a RST packet. This often indicates an error condition."
                              : selectedPacket.errorType === "TCP Reset from Client"
                                ? "The client terminated the connection by sending a RST packet. This may indicate client-side issues."
                                : selectedPacket.errorType === "Failed Handshake"
                                  ? "The TCP handshake process failed to complete. The connection could not be established."
                                  : selectedPacket.errorType === "Connection Timeout"
                                    ? "The connection timed out waiting for a response."
                                    : selectedPacket.errorType === "Duplicate ACK"
                                      ? "Multiple identical ACK packets were sent, indicating potential packet loss."
                                      : selectedPacket.errorType === "Zero Window"
                                        ? "The receiver advertised a zero window size, indicating it cannot accept more data."
                                        : selectedPacket.errorType === "Retransmission"
                                          ? "This packet was retransmitted, possibly due to packet loss or timeout."
                                          : selectedPacket.errorType === "Out of Order"
                                            ? "This packet was received out of sequence."
                                            : "An unknown error occurred with this packet."}
                          </p>
                        </div>
                      )}
                    </TabsContent>
                    <TabsContent value="hex" className="p-4">
                      <div className="font-mono text-xs whitespace-pre overflow-x-auto">
                        {selectedPacket.hexDump?.map((line, index) => (
                          <div key={index}>{line}</div>
                        ))}
                      </div>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardHeader>
                  <CardTitle>Packet Details</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground text-center py-8">Select a packet to view details</p>
                </CardContent>
              </Card>
            )}

            <Card className="mt-4">
              <CardHeader className="pb-2">
                <CardTitle>Connection Summary</CardTitle>
                <CardDescription>
                  {connections.length} connections ({connections.filter((c) => c.hasErrors).length} with errors)
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="rounded-md border overflow-auto max-h-[200px]">
                  <Table>
                    <TableHeader className="sticky top-0 bg-background z-10">
                      <TableRow>
                        <TableHead>Connection</TableHead>
                        <TableHead>Protocol</TableHead>
                        <TableHead>State</TableHead>
                        <TableHead>Packets</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {connections.map((conn) => (
                        <TableRow
                          key={conn.id}
                          className={`${conn.hasErrors ? "bg-red-50" : ""} cursor-pointer hover:bg-muted/50`}
                        >
                          <TableCell className="font-medium">
                            {conn.hasErrors && <AlertTriangle className="h-3 w-3 text-red-500 inline mr-1" />}
                            {`${conn.sourceIp}:${conn.sourcePort} → ${conn.destIp}:${conn.destPort}`}
                          </TableCell>
                          <TableCell>
                            <Badge className={getProtocolColor(conn.protocol)}>{conn.protocol}</Badge>
                          </TableCell>
                          <TableCell className={conn.state === "RESET" ? "text-red-600 font-medium" : ""}>
                            {conn.state}
                          </TableCell>
                          <TableCell>{conn.packets.length}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}
