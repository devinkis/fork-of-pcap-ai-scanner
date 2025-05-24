"use client"

import type React from "react"

import { useState, useEffect, useRef } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Loader2, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"

interface NetworkGraphProps {
  analysisId: string
}

interface Node {
  id: string
  label: string
  type: "host" | "server" | "router" | "unknown"
  connections: number
  packets: number
  bytes: number
  x: number
  y: number
  radius: number
  color: string
  hasErrors: boolean
}

interface Link {
  source: string
  target: string
  value: number
  packets: number
  bytes: number
  protocol: string
  hasErrors: boolean
  errorTypes: string[]
}

interface GraphData {
  nodes: Node[]
  links: Link[]
}

export function NetworkGraph({ analysisId }: NetworkGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [loading, setLoading] = useState(true)
  const [graphData, setGraphData] = useState<GraphData | null>(null)
  const [viewMode, setViewMode] = useState<string>("traffic")
  const [selectedNode, setSelectedNode] = useState<Node | null>(null)
  const [selectedLink, setSelectedLink] = useState<Link | null>(null)
  const [hoveredNode, setHoveredNode] = useState<Node | null>(null)
  const [hoveredLink, setHoveredLink] = useState<Link | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [animationFrame, setAnimationFrame] = useState<number | null>(null)

  // Mouse position and interaction state
  const [isDragging, setIsDragging] = useState(false)
  const [draggedNode, setDraggedNode] = useState<Node | null>(null)
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 })

  useEffect(() => {
    // Generate mock network data
    const generateMockNetworkData = () => {
      const nodes: Node[] = []
      const links: Link[] = []

      // Generate some host nodes
      const hostIPs = ["192.168.1.105", "192.168.1.106", "192.168.1.107", "192.168.1.1", "10.0.0.2", "172.16.0.5"]

      // Generate some server nodes
      const serverIPs = ["203.0.113.42", "8.8.8.8", "8.8.4.4", "104.18.22.46", "172.217.169.78"]

      // Add host nodes
      hostIPs.forEach((ip, index) => {
        nodes.push({
          id: ip,
          label: ip,
          type: "host",
          connections: 0,
          packets: Math.floor(Math.random() * 1000) + 100,
          bytes: Math.floor(Math.random() * 1000000) + 10000,
          x: 200 + Math.random() * 300,
          y: 200 + Math.random() * 300,
          radius: 20,
          color: "hsl(210, 70%, 60%)",
          hasErrors: Math.random() > 0.7,
        })
      })

      // Add server nodes
      serverIPs.forEach((ip, index) => {
        nodes.push({
          id: ip,
          label: ip,
          type: "server",
          connections: 0,
          packets: Math.floor(Math.random() * 5000) + 1000,
          bytes: Math.floor(Math.random() * 10000000) + 1000000,
          x: 600 + Math.random() * 300,
          y: 200 + Math.random() * 300,
          radius: 25,
          color: "hsl(160, 70%, 50%)",
          hasErrors: Math.random() > 0.8,
        })
      })

      // Add router node
      nodes.push({
        id: "192.168.1.1",
        label: "192.168.1.1 (Router)",
        type: "router",
        connections: 0,
        packets: Math.floor(Math.random() * 10000) + 5000,
        bytes: Math.floor(Math.random() * 50000000) + 10000000,
        x: 400,
        y: 300,
        radius: 30,
        color: "hsl(350, 70%, 50%)",
        hasErrors: false,
      })

      // Generate links between nodes
      const protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS"]
      const errorTypes = [
        "TCP Reset",
        "TCP Reset from Client",
        "Failed Handshake",
        "Connection Timeout",
        "Duplicate ACK",
      ]

      // Connect hosts to router
      hostIPs.forEach((hostIP) => {
        if (hostIP !== "192.168.1.1") {
          // Don't connect router to itself
          links.push({
            source: hostIP,
            target: "192.168.1.1",
            value: Math.floor(Math.random() * 10) + 1,
            packets: Math.floor(Math.random() * 1000) + 100,
            bytes: Math.floor(Math.random() * 1000000) + 10000,
            protocol: protocols[Math.floor(Math.random() * protocols.length)],
            hasErrors: Math.random() > 0.8,
            errorTypes: Math.random() > 0.8 ? [errorTypes[Math.floor(Math.random() * errorTypes.length)]] : [],
          })
        }
      })

      // Connect router to servers
      serverIPs.forEach((serverIP) => {
        links.push({
          source: "192.168.1.1",
          target: serverIP,
          value: Math.floor(Math.random() * 10) + 1,
          packets: Math.floor(Math.random() * 1000) + 100,
          bytes: Math.floor(Math.random() * 1000000) + 10000,
          protocol: protocols[Math.floor(Math.random() * protocols.length)],
          hasErrors: Math.random() > 0.8,
          errorTypes: Math.random() > 0.8 ? [errorTypes[Math.floor(Math.random() * errorTypes.length)]] : [],
        })
      })

      // Add some direct connections between hosts and servers
      for (let i = 0; i < 3; i++) {
        const hostIP = hostIPs[Math.floor(Math.random() * hostIPs.length)]
        const serverIP = serverIPs[Math.floor(Math.random() * serverIPs.length)]
        links.push({
          source: hostIP,
          target: serverIP,
          value: Math.floor(Math.random() * 10) + 1,
          packets: Math.floor(Math.random() * 1000) + 100,
          bytes: Math.floor(Math.random() * 1000000) + 10000,
          protocol: protocols[Math.floor(Math.random() * protocols.length)],
          hasErrors: Math.random() > 0.7,
          errorTypes: Math.random() > 0.7 ? [errorTypes[Math.floor(Math.random() * errorTypes.length)]] : [],
        })
      }

      // Update node connections count
      links.forEach((link) => {
        const sourceNode = nodes.find((node) => node.id === link.source)
        const targetNode = nodes.find((node) => node.id === link.target)
        if (sourceNode) sourceNode.connections++
        if (targetNode) targetNode.connections++
      })

      return { nodes, links }
    }

    const fetchNetworkData = async () => {
      try {
        setLoading(true)
        // In a real application, you would fetch the data from an API
        // For demo purposes, we'll use mock data
        await new Promise((resolve) => setTimeout(resolve, 2000))
        const mockData = generateMockNetworkData()
        setGraphData(mockData)
      } catch (err) {
        console.error("Error fetching network data:", err)
        setError("Failed to load network graph data")
      } finally {
        setLoading(false)
      }
    }

    fetchNetworkData()

    return () => {
      if (animationFrame !== null) {
        cancelAnimationFrame(animationFrame)
      }
    }
  }, [analysisId])

  useEffect(() => {
    if (!loading && graphData && canvasRef.current) {
      drawNetworkGraph()
    }
  }, [loading, graphData, viewMode, selectedNode, selectedLink, hoveredNode, hoveredLink])

  const drawNetworkGraph = () => {
    if (!canvasRef.current || !graphData) return

    const canvas = canvasRef.current
    const ctx = canvas.getContext("2d")
    if (!ctx) return

    // Set canvas dimensions
    canvas.width = canvas.offsetWidth
    canvas.height = canvas.offsetHeight

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height)

    // Draw connections
    graphData.links.forEach((link) => {
      const sourceNode = graphData.nodes.find((node) => node.id === link.source)
      const targetNode = graphData.nodes.find((node) => node.id === link.target)

      if (sourceNode && targetNode) {
        ctx.beginPath()
        ctx.moveTo(sourceNode.x, sourceNode.y)
        ctx.lineTo(targetNode.x, targetNode.y)

        // Determine line style based on view mode and selection
        let lineWidth = 1
        let strokeStyle = "rgba(150, 150, 150, 0.5)"

        if (viewMode === "errors" && link.hasErrors) {
          strokeStyle = "rgba(220, 50, 50, 0.7)"
          lineWidth = 2
        } else if (viewMode === "traffic") {
          // Line width based on traffic volume
          lineWidth = Math.max(1, Math.min(8, link.value))
          strokeStyle = "rgba(100, 100, 200, 0.5)"
        } else if (viewMode === "protocols") {
          // Color based on protocol
          switch (link.protocol) {
            case "TCP":
              strokeStyle = "rgba(0, 150, 255, 0.6)"
              break
            case "UDP":
              strokeStyle = "rgba(0, 200, 100, 0.6)"
              break
            case "HTTP":
              strokeStyle = "rgba(180, 0, 180, 0.6)"
              break
            case "HTTPS":
              strokeStyle = "rgba(100, 0, 200, 0.6)"
              break
            case "DNS":
              strokeStyle = "rgba(255, 180, 0, 0.6)"
              break
            default:
              strokeStyle = "rgba(150, 150, 150, 0.5)"
          }
        }

        // Highlight selected or hovered link
        if (
          selectedLink &&
          ((selectedLink.source === link.source && selectedLink.target === link.target) ||
            (selectedLink.source === link.target && selectedLink.target === link.source))
        ) {
          lineWidth += 2
          strokeStyle = "rgba(50, 150, 255, 0.9)"
        } else if (
          hoveredLink &&
          ((hoveredLink.source === link.source && hoveredLink.target === link.target) ||
            (hoveredLink.source === link.target && hoveredLink.target === link.source))
        ) {
          lineWidth += 1
          strokeStyle = "rgba(100, 180, 255, 0.8)"
        }

        // Highlight links connected to selected node
        if (selectedNode && (link.source === selectedNode.id || link.target === selectedNode.id)) {
          lineWidth += 1
          strokeStyle = "rgba(100, 180, 255, 0.8)"
        }

        ctx.lineWidth = lineWidth
        ctx.strokeStyle = strokeStyle
        ctx.stroke()

        // Draw arrow to indicate direction
        const angle = Math.atan2(targetNode.y - sourceNode.y, targetNode.x - sourceNode.x)
        const arrowLength = 10
        const arrowWidth = 5
        const arrowX = targetNode.x - targetNode.radius * Math.cos(angle)
        const arrowY = targetNode.y - targetNode.radius * Math.sin(angle)

        ctx.beginPath()
        ctx.moveTo(arrowX, arrowY)
        ctx.lineTo(
          arrowX - arrowLength * Math.cos(angle) + arrowWidth * Math.sin(angle),
          arrowY - arrowLength * Math.sin(angle) - arrowWidth * Math.cos(angle),
        )
        ctx.lineTo(
          arrowX - arrowLength * Math.cos(angle) - arrowWidth * Math.sin(angle),
          arrowY - arrowLength * Math.sin(angle) + arrowWidth * Math.cos(angle),
        )
        ctx.closePath()
        ctx.fillStyle = strokeStyle
        ctx.fill()
      }
    })

    // Draw nodes
    graphData.nodes.forEach((node) => {
      // Determine node style based on view mode and selection
      let radius = node.radius
      const fillStyle = node.color
      let strokeStyle = "rgba(50, 50, 50, 0.8)"
      let lineWidth = 1

      if (viewMode === "errors" && node.hasErrors) {
        strokeStyle = "rgba(220, 50, 50, 0.9)"
        lineWidth = 3
      }

      // Highlight selected or hovered node
      if (selectedNode && selectedNode.id === node.id) {
        radius += 5
        strokeStyle = "rgba(50, 150, 255, 0.9)"
        lineWidth = 3
      } else if (hoveredNode && hoveredNode.id === node.id) {
        radius += 2
        strokeStyle = "rgba(100, 180, 255, 0.8)"
        lineWidth = 2
      }

      // Draw circle
      ctx.beginPath()
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2)
      ctx.fillStyle = fillStyle
      ctx.fill()
      ctx.lineWidth = lineWidth
      ctx.strokeStyle = strokeStyle
      ctx.stroke()

      // Draw node type icon
      ctx.fillStyle = "rgba(255, 255, 255, 0.9)"
      ctx.font = "bold 14px sans-serif"
      ctx.textAlign = "center"
      ctx.textBaseline = "middle"

      if (node.type === "router") {
        ctx.fillText("R", node.x, node.y)
      } else if (node.type === "server") {
        ctx.fillText("S", node.x, node.y)
      } else {
        ctx.fillText("H", node.x, node.y)
      }

      // Draw label
      ctx.font = "12px sans-serif"
      ctx.fillStyle = "#333"
      ctx.textAlign = "center"
      ctx.fillText(node.label, node.x, node.y + radius + 15)

      // Draw error indicator if needed
      if (node.hasErrors) {
        ctx.beginPath()
        ctx.arc(node.x + radius - 5, node.y - radius + 5, 5, 0, Math.PI * 2)
        ctx.fillStyle = "rgba(220, 50, 50, 0.9)"
        ctx.fill()
        ctx.lineWidth = 1
        ctx.strokeStyle = "white"
        ctx.stroke()
      }
    })
  }

  const handleCanvasMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!canvasRef.current || !graphData) return

    const canvas = canvasRef.current
    const rect = canvas.getBoundingClientRect()
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top
    setMousePos({ x, y })

    // Check if mouse is over a node
    let foundNode = null
    for (const node of graphData.nodes) {
      const distance = Math.sqrt(Math.pow(node.x - x, 2) + Math.pow(node.y - y, 2))
      if (distance <= node.radius) {
        foundNode = node
        break
      }
    }

    // Check if mouse is over a link
    let foundLink = null
    if (!foundNode) {
      for (const link of graphData.links) {
        const sourceNode = graphData.nodes.find((node) => node.id === link.source)
        const targetNode = graphData.nodes.find((node) => node.id === link.target)
        if (sourceNode && targetNode) {
          // Calculate distance from point to line
          const lineLength = Math.sqrt(
            Math.pow(targetNode.x - sourceNode.x, 2) + Math.pow(targetNode.y - sourceNode.y, 2),
          )
          const distance =
            Math.abs(
              (targetNode.y - sourceNode.y) * x -
                (targetNode.x - sourceNode.x) * y +
                targetNode.x * sourceNode.y -
                targetNode.y * sourceNode.x,
            ) / lineLength

          // Check if point is close to line and between endpoints
          if (distance < 10) {
            // Check if point is between endpoints
            const dotProduct =
              ((x - sourceNode.x) * (targetNode.x - sourceNode.x) +
                (y - sourceNode.y) * (targetNode.y - sourceNode.y)) /
              Math.pow(lineLength, 2)
            if (dotProduct >= 0 && dotProduct <= 1) {
              foundLink = link
              break
            }
          }
        }
      }
    }

    // Update hovered node and link
    setHoveredNode(foundNode)
    setHoveredLink(foundLink)

    // Handle dragging
    if (isDragging && draggedNode) {
      // Update node position
      const updatedNodes = graphData.nodes.map((node) => {
        if (node.id === draggedNode.id) {
          return { ...node, x, y }
        }
        return node
      })
      setGraphData({ ...graphData, nodes: updatedNodes })
    }

    // Update cursor style
    if (foundNode || isDragging) {
      canvas.style.cursor = "pointer"
    } else if (foundLink) {
      canvas.style.cursor = "crosshair"
    } else {
      canvas.style.cursor = "default"
    }
  }

  const handleCanvasMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (hoveredNode) {
      setIsDragging(true)
      setDraggedNode(hoveredNode)
    }
  }

  const handleCanvasMouseUp = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (isDragging && draggedNode) {
      // End dragging
      setIsDragging(false)
      setDraggedNode(null)
    } else {
      // Handle click
      if (hoveredNode) {
        setSelectedNode(hoveredNode === selectedNode ? null : hoveredNode)
        setSelectedLink(null)
      } else if (hoveredLink) {
        setSelectedLink(hoveredLink === selectedLink ? null : hoveredLink)
        setSelectedNode(null)
      } else {
        setSelectedNode(null)
        setSelectedLink(null)
      }
    }
  }

  const handleCanvasMouseLeave = () => {
    setHoveredNode(null)
    setHoveredLink(null)
    setIsDragging(false)
    setDraggedNode(null)
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
      <Card>
        <CardHeader className="pb-2">
          <div className="flex justify-between items-center">
            <div>
              <CardTitle>Network Communication Graph</CardTitle>
              <CardDescription>Visual representation of network traffic patterns</CardDescription>
            </div>
            <Select value={viewMode} onValueChange={setViewMode}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="View mode" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="traffic">Traffic Volume</SelectItem>
                <SelectItem value="protocols">Protocol Types</SelectItem>
                <SelectItem value="errors">Error Detection</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center items-center h-[500px]">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="h-[500px] w-full relative">
              <canvas
                ref={canvasRef}
                className="w-full h-full"
                onMouseMove={handleCanvasMouseMove}
                onMouseDown={handleCanvasMouseDown}
                onMouseUp={handleCanvasMouseUp}
                onMouseLeave={handleCanvasMouseLeave}
              />
              {(selectedNode || selectedLink) && (
                <div className="absolute bottom-4 right-4 bg-white p-3 rounded-md shadow-md border max-w-xs">
                  {selectedNode && (
                    <div>
                      <h4 className="font-medium">{selectedNode.label}</h4>
                      <div className="text-sm mt-1">
                        <div>Type: {selectedNode.type.charAt(0).toUpperCase() + selectedNode.type.slice(1)}</div>
                        <div>Connections: {selectedNode.connections}</div>
                        <div>Packets: {selectedNode.packets.toLocaleString()}</div>
                        <div>Data: {(selectedNode.bytes / 1024).toFixed(2)} KB</div>
                        {selectedNode.hasErrors && (
                          <div className="text-red-500 flex items-center mt-1">
                            <AlertTriangle className="h-4 w-4 mr-1" /> Has network errors
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  {selectedLink && (
                    <div>
                      <h4 className="font-medium">
                        {selectedLink.source} → {selectedLink.target}
                      </h4>
                      <div className="text-sm mt-1">
                        <div>Protocol: {selectedLink.protocol}</div>
                        <div>Packets: {selectedLink.packets.toLocaleString()}</div>
                        <div>Data: {(selectedLink.bytes / 1024).toFixed(2)} KB</div>
                        {selectedLink.hasErrors && (
                          <div>
                            <div className="text-red-500 flex items-center mt-1">
                              <AlertTriangle className="h-4 w-4 mr-1" /> Network errors detected
                            </div>
                            {selectedLink.errorTypes.map((error, index) => (
                              <div key={index} className="text-red-500 text-xs ml-5 mt-1">
                                • {error}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Network Statistics</CardTitle>
          <CardDescription>Summary of network traffic and anomalies</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="summary">
            <TabsList>
              <TabsTrigger value="summary">Summary</TabsTrigger>
              <TabsTrigger value="protocols">Protocols</TabsTrigger>
              <TabsTrigger value="errors">Errors</TabsTrigger>
            </TabsList>
            <TabsContent value="summary" className="pt-4">
              {loading ? (
                <div className="flex justify-center items-center h-40">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-muted/50 p-4 rounded-lg">
                    <div className="text-sm text-muted-foreground">Total Hosts</div>
                    <div className="text-2xl font-bold mt-1">
                      {graphData?.nodes.filter((n) => n.type === "host").length || 0}
                    </div>
                  </div>
                  <div className="bg-muted/50 p-4 rounded-lg">
                    <div className="text-sm text-muted-foreground">Total Connections</div>
                    <div className="text-2xl font-bold mt-1">{graphData?.links.length || 0}</div>
                  </div>
                  <div className="bg-muted/50 p-4 rounded-lg">
                    <div className="text-sm text-muted-foreground">Error Rate</div>
                    <div className="text-2xl font-bold mt-1">
                      {graphData
                        ? Math.round((graphData.links.filter((l) => l.hasErrors).length / graphData.links.length) * 100)
                        : 0}
                      %
                    </div>
                  </div>
                </div>
              )}
            </TabsContent>
            <TabsContent value="protocols" className="pt-4">
              {loading ? (
                <div className="flex justify-center items-center h-40">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                  {graphData &&
                    ["TCP", "UDP", "HTTP", "HTTPS", "DNS"].map((protocol) => {
                      const count = graphData.links.filter((l) => l.protocol === protocol).length
                      const percentage = Math.round((count / graphData.links.length) * 100)
                      return (
                        <div key={protocol} className="bg-muted/50 p-4 rounded-lg">
                          <div className="flex justify-between items-center">
                            <div className="text-sm text-muted-foreground">{protocol}</div>
                            <Badge variant="outline">{percentage}%</Badge>
                          </div>
                          <div className="text-xl font-bold mt-1">{count}</div>
                        </div>
                      )
                    })}
                </div>
              )}
            </TabsContent>
            <TabsContent value="errors" className="pt-4">
              {loading ? (
                <div className="flex justify-center items-center h-40">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {graphData &&
                    ["TCP Reset", "Failed Handshake", "Connection Timeout", "Duplicate ACK"].map((errorType) => {
                      const count = graphData.links.filter((l) => l.errorTypes.includes(errorType)).length
                      return (
                        <div key={errorType} className="bg-red-50 p-4 rounded-lg border border-red-100">
                          <div className="flex items-center">
                            <AlertTriangle className="h-4 w-4 text-red-500 mr-2" />
                            <div className="text-sm font-medium text-red-700">{errorType}</div>
                          </div>
                          <div className="text-xl font-bold mt-1 text-red-800">{count}</div>
                        </div>
                      )
                    })}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
