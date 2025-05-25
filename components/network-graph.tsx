// components/network-graph.tsx
"use client";

import React, { useState, useEffect, useRef, useCallback } from "react"; // Tambahkan useCallback
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Loader2, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge"

interface NetworkGraphProps {
  analysisId: string;
}

interface Node {
  id: string; // IP Address
  label: string; // IP Address atau nama host jika ada
  type: "host" | "server" | "router" | "unknown"; // Tipe node bisa kita tentukan nanti
  connections: number; // Jumlah link yang terhubung
  packets: number; // Total paket yang melibatkan node ini
  bytes: number; // Total byte yang melibatkan node ini
  x: number;
  y: number;
  radius: number;
  color: string;
  hasErrors: boolean; // Jika ada koneksi error yang melibatkan node ini
}

interface Link {
  source: string; // IP source node
  target: string; // IP destination node
  value: number; // Bobot link, misal berdasarkan jumlah paket atau byte
  packets: number;
  bytes: number;
  protocol: string;
  hasErrors: boolean;
  errorTypes?: string[]; // Jika ada error pada koneksi ini
  // Tambahkan properti lain jika perlu, misal port
  sourcePort?: number;
  destPort?: number;
}

interface GraphData {
  nodes: Node[];
  links: Link[];
}

// Tipe data koneksi dari API /api/get-packet-data/[id]
interface ApiConnection {
  id: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: string;
  state: string;
  packets: number[]; // Array ID paket, kita akan gunakan length-nya
  startTime: string;
  endTime?: string;
  hasErrors: boolean;
  errorTypes: string[];
  // Kita mungkin perlu menambahkan totalBytes per koneksi dari API jika ingin digunakan untuk 'value'
}


export function NetworkGraph({ analysisId }: NetworkGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [loading, setLoading] = useState(true);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [viewMode, setViewMode] = useState<string>("traffic"); // traffic, protocols, errors
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [selectedLink, setSelectedLink] = useState<Link | null>(null);
  const [hoveredNode, setHoveredNode] = useState<Node | null>(null);
  const [hoveredLink, setHoveredLink] = useState<Link | null>(null);
  const [error, setError] = useState<string | null>(null);
  // State untuk interaksi mouse (dragging, etc.) tetap sama
  const [isDragging, setIsDragging] = useState(false);
  const [draggedNode, setDraggedNode] = useState<Node | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  const transformApiDataToGraphData = (connections: ApiConnection[]): GraphData => {
    const nodesMap = new Map<string, Node>();
    const links: Link[] = [];
    const ipPacketCount: Record<string, number> = {};
    const ipByteCount: Record<string, number> = {}; // Untuk menghitung total byte per IP
    const ipConnectionCount: Record<string, number> = {};
    const ipErrorStatus: Record<string, boolean> = {};


    connections.forEach(conn => {
      // Hitung total paket dan byte per koneksi (jika API tidak menyediakannya)
      // Untuk saat ini, kita gunakan conn.packets.length sebagai jumlah paket
      // Untuk bytes, kita perlu data byte per paket atau total byte per koneksi dari API
      // Jika tidak ada, kita bisa set default atau menghitungnya jika ada data paket individual
      const connectionPackets = conn.packets.length;
      const connectionBytes = connectionPackets * 150; // Asumsi rata-rata ukuran paket jika tidak ada data byte

      // Tambahkan node jika belum ada
      [conn.sourceIp, conn.destIp].forEach(ip => {
        if (!nodesMap.has(ip)) {
          nodesMap.set(ip, {
            id: ip,
            label: ip,
            type: "unknown", // Tipe bisa ditentukan lebih lanjut
            connections: 0,
            packets: 0,
            bytes: 0,
            x: Math.random() * (canvasRef.current?.width || 800) * 0.8 + (canvasRef.current?.width || 800) * 0.1,
            y: Math.random() * (canvasRef.current?.height || 500) * 0.8 + (canvasRef.current?.height || 500) * 0.1,
            radius: 15, // Radius awal
            color: `hsl(${Math.random() * 360}, 70%, 60%)`,
            hasErrors: false,
          });
        }
        // Agregasi data untuk node
        const node = nodesMap.get(ip)!;
        ipPacketCount[ip] = (ipPacketCount[ip] || 0) + connectionPackets;
        ipByteCount[ip] = (ipByteCount[ip] || 0) + connectionBytes; // Asumsi
        ipConnectionCount[ip] = (ipConnectionCount[ip] || 0) + 1;
        if (conn.hasErrors) {
            ipErrorStatus[ip] = true;
        }
      });

      // Tambahkan link
      links.push({
        source: conn.sourceIp,
        target: conn.destIp,
        value: connectionPackets, // Bobot link berdasarkan jumlah paket
        packets: connectionPackets,
        bytes: connectionBytes, // Asumsi
        protocol: conn.protocol,
        hasErrors: conn.hasErrors,
        errorTypes: conn.errorTypes,
        sourcePort: conn.sourcePort,
        destPort: conn.destPort,
      });
    });

    // Finalisasi data node
    nodesMap.forEach(node => {
      node.packets = ipPacketCount[node.id] || 0;
      node.bytes = ipByteCount[node.id] || 0;
      node.connections = ipConnectionCount[node.id] || 0;
      node.hasErrors = ipErrorStatus[node.id] || false;
      // Sesuaikan radius berdasarkan jumlah koneksi atau paket
      node.radius = 10 + Math.min(Math.sqrt(node.packets / 10 + node.connections * 2), 20);
      // Tentukan tipe node (contoh sederhana)
      if (node.id.startsWith("192.168.") || node.id.startsWith("10.") || node.id.startsWith("172.16.")) {
        node.type = "host";
        node.color = "hsl(210, 70%, 60%)";
      } else if (node.connections === 1 && node.packets > 1000) { // Heuristik sederhana untuk server
        node.type = "server";
        node.color = "hsl(160, 70%, 50%)";
      } else {
        node.type = "unknown";
      }
    });

    return { nodes: Array.from(nodesMap.values()), links };
  };

  const fetchNetworkData = useCallback(async () => {
    setLoading(true);
    setError(null);
    setGraphData(null); // Bersihkan data lama
    console.log(`[NetworkGraph] Fetching data for analysisId: ${analysisId}`);
    try {
      // Panggil API /api/get-packet-data/[id]
      const response = await fetch(`/api/get-packet-data/${analysisId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Failed to fetch packet data: ${response.statusText}`);
      }
      const apiResult = await response.json();

      if (apiResult.success && apiResult.connections) {
        console.log(`[NetworkGraph] Received ${apiResult.connections.length} connections from API.`);
        if (apiResult.connections.length > 0) {
            const transformedData = transformApiDataToGraphData(apiResult.connections);
            setGraphData(transformedData);
        } else {
            setGraphData({ nodes: [], links: [] }); // Set data kosong jika tidak ada koneksi
            console.log("[NetworkGraph] No connections data to visualize.");
        }
      } else {
        throw new Error(apiResult.error || "Invalid data structure received from API.");
      }
    } catch (err) {
      console.error("[NetworkGraph] Error fetching or transforming network data:", err);
      setError(err instanceof Error ? err.message : "Failed to load network graph data.");
    } finally {
      setLoading(false);
    }
  }, [analysisId]); // Hapus transformApiDataToGraphData dari dependencies karena ia didefinisikan di scope yang sama

  useEffect(() => {
    if (analysisId) {
        fetchNetworkData();
    }
  }, [analysisId, fetchNetworkData]);

  // Fungsi drawNetworkGraph, handleCanvasMouseMove, handleCanvasMouseDown, handleCanvasMouseUp, handleCanvasMouseLeave
  // tetap sama seperti yang sudah Anda miliki di components/network-graph.tsx.
  // Pastikan di drawNetworkGraph, Anda menggunakan graphData.nodes dan graphData.links
  const drawNetworkGraph = useCallback(() => {
    if (!canvasRef.current || !graphData) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw connections (links)
    graphData.links.forEach((link) => {
      const sourceNode = graphData.nodes.find((node) => node.id === link.source);
      const targetNode = graphData.nodes.find((node) => node.id === link.target);

      if (sourceNode && targetNode) {
        ctx.beginPath();
        ctx.moveTo(sourceNode.x, sourceNode.y);
        ctx.lineTo(targetNode.x, targetNode.y);

        let lineWidth = 1;
        let strokeStyle = "rgba(150, 150, 150, 0.3)"; // Lebih transparan defaultnya

        if (viewMode === "errors" && link.hasErrors) {
          strokeStyle = "rgba(220, 50, 50, 0.7)";
          lineWidth = 2.5;
        } else if (viewMode === "traffic") {
          lineWidth = Math.max(1, Math.min(10, Math.log(link.bytes / 1000 + 1) * 0.8 )); // Skala logaritmik untuk bytes
          strokeStyle = `rgba(100, 100, 200, ${Math.min(0.2 + link.packets / 500, 0.7)})`; // Opacity berdasarkan jumlah paket
        } else if (viewMode === "protocols") {
          // ... (logika warna protokol tetap sama)
           switch (link.protocol?.toUpperCase()) {
            case "TCP": strokeStyle = "rgba(0, 150, 255, 0.6)"; break;
            case "UDP": strokeStyle = "rgba(0, 200, 100, 0.6)"; break;
            case "HTTP": strokeStyle = "rgba(180, 0, 180, 0.6)"; break;
            case "HTTPS": case "TLS": strokeStyle = "rgba(100, 0, 200, 0.6)"; break;
            case "DNS": strokeStyle = "rgba(255, 180, 0, 0.6)"; break;
            case "ICMP": strokeStyle = "rgba(255, 100, 0, 0.6)"; break;
            default: strokeStyle = "rgba(180, 180, 180, 0.4)";
          }
        }

        if (selectedLink && selectedLink.source === link.source && selectedLink.target === link.target) {
          lineWidth += 2; strokeStyle = "rgba(50, 150, 255, 1)";
        } else if (hoveredLink && hoveredLink.source === link.source && hoveredLink.target === link.target) {
          lineWidth += 1; strokeStyle = "rgba(100, 180, 255, 0.9)";
        }
        if (selectedNode && (link.source === selectedNode.id || link.target === selectedNode.id)) {
          lineWidth = Math.max(lineWidth, 2); strokeStyle = hoveredLink && hoveredLink.source === link.source && hoveredLink.target === link.target ? "rgba(50, 150, 255, 1)" : "rgba(100, 180, 255, 0.8)";
        }


        ctx.lineWidth = lineWidth;
        ctx.strokeStyle = strokeStyle;
        ctx.stroke();

        // Opsi: Gambar panah di tengah link jika diperlukan
        // const midX = (sourceNode.x + targetNode.x) / 2;
        // const midY = (sourceNode.y + targetNode.y) / 2;
        // const angle = Math.atan2(targetNode.y - sourceNode.y, targetNode.x - sourceNode.x);
        // ctx.save();
        // ctx.translate(midX, midY);
        // ctx.rotate(angle);
        // ctx.beginPath();
        // ctx.moveTo(0, 0);
        // ctx.lineTo(-8, -4);
        // ctx.lineTo(-8, 4);
        // ctx.closePath();
        // ctx.fillStyle = strokeStyle;
        // ctx.fill();
        // ctx.restore();
      }
    });

    // Draw nodes
    graphData.nodes.forEach((node) => {
      let radius = node.radius;
      let fillStyle = node.color;
      let nodeStrokeStyle = "rgba(50, 50, 50, 0.8)";
      let nodeLineWidth = 1;

      if (viewMode === "errors" && node.hasErrors) {
        nodeStrokeStyle = "rgba(220, 50, 50, 0.9)";
        nodeLineWidth = 3;
      }

      if (selectedNode && selectedNode.id === node.id) {
        radius += 4; nodeStrokeStyle = "rgba(50, 150, 255, 1)"; nodeLineWidth = 3;
      } else if (hoveredNode && hoveredNode.id === node.id) {
        radius += 2; nodeStrokeStyle = "rgba(100, 180, 255, 0.9)"; nodeLineWidth = 2;
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = fillStyle;
      ctx.fill();
      ctx.lineWidth = nodeLineWidth;
      ctx.strokeStyle = nodeStrokeStyle;
      ctx.stroke();

      // Draw label
      ctx.font = "11px sans-serif";
      ctx.fillStyle = "#333"; // Ganti warna teks agar kontras dengan tema gelap/terang
      ctx.textAlign = "center";
      ctx.fillText(node.label, node.x, node.y + radius + 12);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphData, viewMode, selectedNode, selectedLink, hoveredNode, hoveredLink]); // Tambahkan dependensi

  useEffect(() => {
    if (graphData && canvasRef.current) {
      const animationId = requestAnimationFrame(drawNetworkGraph);
      return () => cancelAnimationFrame(animationId);
    }
  }, [graphData, drawNetworkGraph]);


  // Mouse handlers (handleCanvasMouseMove, handleCanvasMouseDown, handleCanvasMouseUp, handleCanvasMouseLeave)
  // bisa disalin dari versi mock data Anda, pastikan mereka menggunakan `graphData` yang baru.
    const handleCanvasMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
        if (!canvasRef.current || !graphData) return;
        const canvas = canvasRef.current;
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        setMousePos({ x, y });

        let foundNode: Node | null = null;
        for (const node of graphData.nodes) {
        const distance = Math.sqrt(Math.pow(node.x - x, 2) + Math.pow(node.y - y, 2));
        if (distance <= node.radius + 5) { // Tambah sedikit toleransi klik
            foundNode = node;
            break;
        }
        }
        setHoveredNode(foundNode);

        let foundLink: Link | null = null;
        if (!foundNode) {
            for (const link of graphData.links) {
                const sourceNode = graphData.nodes.find(n => n.id === link.source);
                const targetNode = graphData.nodes.find(n => n.id === link.target);
                if (sourceNode && targetNode) {
                    const dx = targetNode.x - sourceNode.x;
                    const dy = targetNode.y - sourceNode.y;
                    const lenSq = dx * dx + dy * dy;
                    const dot = ((x - sourceNode.x) * dx + (y - sourceNode.y) * dy) / lenSq;
                    const closestX = sourceNode.x + dot * dx;
                    const closestY = sourceNode.y + dot * dy;
                    const onSegment = dot >= 0 && dot <= 1;
                    if (onSegment) {
                        const distToLine = Math.sqrt(Math.pow(x - closestX, 2) + Math.pow(y - closestY, 2));
                        if (distToLine < 8) { // Toleransi klik untuk link
                            foundLink = link;
                            break;
                        }
                    }
                }
            }
        }
        setHoveredLink(foundLink);


        if (isDragging && draggedNode && graphData) {
        const updatedNodes = graphData.nodes.map(node =>
            node.id === draggedNode.id ? { ...node, x, y } : node
        );
        setGraphData({ ...graphData, nodes: updatedNodes });
        }
        canvas.style.cursor = foundNode || isDragging ? 'grab' : foundLink ? 'pointer' : 'default';
    };

    const handleCanvasMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
        if (hoveredNode) {
        setIsDragging(true);
        setDraggedNode(hoveredNode);
        canvasRef.current!.style.cursor = 'grabbing';
        }
    };

    const handleCanvasMouseUp = () => {
        if (isDragging) {
        setIsDragging(false);
        setDraggedNode(null);
        canvasRef.current!.style.cursor = hoveredNode ? 'grab' : 'default';
        } else {
          // Handle click jika tidak dragging
          if (hoveredNode) {
            setSelectedNode(hoveredNode === selectedNode ? null : hoveredNode);
            setSelectedLink(null);
          } else if (hoveredLink) {
            setSelectedLink(hoveredLink === selectedLink ? null : hoveredLink);
            setSelectedNode(null);
          } else if (!hoveredNode && !hoveredLink) { // Klik di area kosong
             setSelectedNode(null);
             setSelectedLink(null);
          }
        }
    };
    const handleCanvasMouseLeave = () => {
        setHoveredNode(null);
        setHoveredLink(null);
        if (isDragging) { // Jika keluar canvas saat dragging, batalkan drag
            setIsDragging(false);
            setDraggedNode(null);
        }
        if(canvasRef.current) canvasRef.current.style.cursor = 'default';
    };


  if (error) {
    return (
      <Card className="col-span-1 md:col-span-2 lg:col-span-3">
        <CardHeader>
          <CardTitle className="text-destructive flex items-center">
            <AlertTriangle className="mr-2 h-5 w-5" />
            Error Loading Network Graph
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p>{error}</p>
          <Button onClick={() => fetchNetworkData()} className="mt-4">Try Again</Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
            <div>
              <CardTitle>Network Communication Graph</CardTitle>
              <CardDescription>Visual representation of network connections.</CardDescription>
            </div>
            <div className="flex items-center gap-2">
                <Select value={viewMode} onValueChange={setViewMode}>
                    <SelectTrigger className="w-[180px] h-9 text-xs">
                        <SelectValue placeholder="View mode" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="traffic">Traffic Volume</SelectItem>
                        <SelectItem value="protocols">Protocol Types</SelectItem>
                        <SelectItem value="errors">Error Highlighting</SelectItem>
                    </SelectContent>
                </Select>
                <Button onClick={() => fetchNetworkData()} size="sm" variant="outline" disabled={loading}>
                    <Loader2 className={`mr-2 h-4 w-4 ${loading ? 'animate-spin': 'hidden'}`} />
                    Refresh Graph
                </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading && !graphData ? ( // Tampilkan loading hanya jika graphData belum ada
            <div className="flex justify-center items-center h-[400px] md:h-[500px]">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              <p className="ml-2 text-muted-foreground">Loading graph data...</p>
            </div>
          ) : (!graphData || graphData.nodes.length === 0) && !loading ? (
            <div className="flex justify-center items-center h-[400px] md:h-[500px] text-muted-foreground">
                <p>No network connection data to display for this PCAP.</p>
            </div>
          ) : (
            <div className="h-[400px] md:h-[500px] w-full relative border rounded-md overflow-hidden bg-slate-50 dark:bg-slate-800/30">
              <canvas
                ref={canvasRef}
                className="w-full h-full"
                onMouseMove={handleCanvasMouseMove}
                onMouseDown={handleCanvasMouseDown}
                onMouseUp={handleCanvasMouseUp}
                onMouseLeave={handleCanvasMouseLeave}
              />
              {/* Tooltip atau info panel untuk node/link yang di-hover atau dipilih */}
              {(selectedNode || selectedLink || hoveredNode || hoveredLink) && (
                <div className="absolute bottom-2 right-2 bg-background/80 backdrop-blur-sm p-3 rounded-md shadow-lg border max-w-xs text-xs z-10">
                  { (selectedNode || hoveredNode) && (selectedNode || hoveredNode)!.id &&
                    <div>
                      <h4 className="font-semibold text-sm">{(selectedNode || hoveredNode)!.label}</h4>
                      <p>Type: {(selectedNode || hoveredNode)!.type}</p>
                      <p>Connections: {(selectedNode || hoveredNode)!.connections}</p>
                      <p>Packets: {(selectedNode || hoveredNode)!.packets.toLocaleString()}</p>
                      <p>Bytes: {((selectedNode || hoveredNode)!.bytes / 1024).toFixed(2)} KB</p>
                      {(selectedNode || hoveredNode)!.hasErrors && <p className="text-red-500 flex items-center"><AlertTriangle size={14} className="mr-1"/> Contains errors</p>}
                    </div>
                  }
                  { (selectedLink || hoveredLink) && (selectedLink || hoveredLink)!.source &&
                    <div className={ (selectedNode || hoveredNode) ? "mt-2 pt-2 border-t" : ""}>
                      <h4 className="font-semibold text-sm">
                        {(selectedLink || hoveredLink)!.source.split(':')[0]} 
                        { (selectedLink || hoveredLink)!.sourcePort ? `:${(selectedLink || hoveredLink)!.sourcePort}`:''} → {(selectedLink || hoveredLink)!.target.split(':')[0]}
                        { (selectedLink || hoveredLink)!.destPort ? `:${(selectedLink || hoveredLink)!.destPort}`:''}
                      </h4>
                      <p>Protocol: {(selectedLink || hoveredLink)!.protocol}</p>
                      <p>Packets: {(selectedLink || hoveredLink)!.packets.toLocaleString()}</p>
                      <p>Bytes: {((selectedLink || hoveredLink)!.bytes / 1024).toFixed(2)} KB</p>
                      {(selectedLink || hoveredLink)!.hasErrors && <p className="text-red-500 flex items-center"><AlertTriangle size={14} className="mr-1"/> Contains errors</p>}
                    </div>
                  }
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      {/* Informasi tambahan atau legenda bisa ditambahkan di sini jika perlu */}
    </div>
  );
}
