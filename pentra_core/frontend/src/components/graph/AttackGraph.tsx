"use client";

import React, { useCallback, useState } from 'react';
import {
    ReactFlow,
    MiniMap,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    addEdge,
    Connection,
    Edge,
    MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import CyberNode from './CyberNode';
import { Button } from '../ui/button';
import { ScanSearch, Maximize, Share2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { SeverityBadge } from '../ui/severity-badge';

const nodeTypes = {
    cyberNode: CyberNode,
};

// Initial Nodes
const initialNodes = [
    { id: 'start', type: 'cyberNode', position: { x: 400, y: 50 }, data: { label: 'INTERNET', type: 'access' } },
    { id: 'waf', type: 'cyberNode', position: { x: 400, y: 150 }, data: { label: 'Cloudflare WAF', type: 'service' } },
    { id: 'web', type: 'cyberNode', position: { x: 400, y: 250 }, data: { label: 'banking-api.prod', type: 'asset' } },
    { id: 'vuln1', type: 'cyberNode', position: { x: 250, y: 350 }, data: { label: 'CVE-2024-29510', type: 'vulnerability', isCompromised: true } },
    { id: 'vuln2', type: 'cyberNode', position: { x: 550, y: 350 }, data: { label: 'SQLi (Blind)', type: 'vulnerability' } },
    { id: 'cred', type: 'cyberNode', position: { x: 250, y: 450 }, data: { label: 'AWS Access Key', type: 'credential', isCompromised: true } },
    { id: 'db', type: 'cyberNode', position: { x: 550, y: 450 }, data: { label: 'PostgreSQL DB', type: 'asset' } },
    { id: 'aws', type: 'cyberNode', position: { x: 250, y: 550 }, data: { label: 'S3 Buckets (PII)', type: 'asset', isCompromised: true } },
];

// Initial Edges
const initialEdges = [
    { id: 'e1', source: 'start', target: 'waf', animated: true, style: { stroke: '#00eaff' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#00eaff' } },
    { id: 'e2', source: 'waf', target: 'web', animated: true, style: { stroke: '#00eaff' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#00eaff' } },
    { id: 'e3', source: 'web', target: 'vuln1', label: 'Discovered', style: { stroke: '#ff003c', strokeWidth: 2 }, className: 'drop-shadow-[0_0_8px_rgba(255,0,60,0.8)]', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#ff003c' } },
    { id: 'e4', source: 'web', target: 'vuln2', style: { stroke: '#ff5a1f' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#ff5a1f' } },
    { id: 'e5', source: 'vuln1', target: 'cred', label: 'Exploited', style: { stroke: '#ff003c', strokeWidth: 2 }, className: 'drop-shadow-[0_0_8px_rgba(255,0,60,0.8)]', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#ff003c' } },
    { id: 'e6', source: 'vuln2', target: 'db', style: { stroke: '#ff5a1f' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#ff5a1f' } },
    { id: 'e7', source: 'cred', target: 'aws', label: 'Lateral Movement', style: { stroke: '#ff003c', strokeWidth: 2 }, className: 'drop-shadow-[0_0_8px_rgba(255,0,60,0.8)]', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#ff003c' } },
];

export default function AttackGraph() {
    const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes as any);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges as any);
    const [selectedNode, setSelectedNode] = useState<any>(null);

    const onConnect = useCallback((params: Edge | Connection) => setEdges((els) => addEdge(params, els)), [setEdges]);

    const handleNodeClick = (event: React.MouseEvent, node: any) => {
        setSelectedNode(node);
    };

    const handlePaneClick = () => {
        setSelectedNode(null);
    };

    return (
        <div className="relative w-full h-[600px] border border-pentra-border bg-pentra-black">
            {/* Toolbar overlay */}
            <div className="absolute top-4 left-4 z-10 flex gap-2">
                <Button variant="outline" size="sm" className="bg-pentra-panel border-pentra-border-strong text-pentra-cyan gap-2">
                    <ScanSearch size={14} /> HIGHLIGHT CRITICAL
                </Button>
                <Button variant="outline" size="sm" className="bg-pentra-panel border-pentra-border-strong text-pentra-text-muted gap-2">
                    <Maximize size={14} /> FULLSCREEN
                </Button>
                <Button variant="outline" size="sm" className="bg-pentra-panel border-pentra-border-strong text-pentra-text-muted gap-2">
                    <Share2 size={14} /> EXPORT
                </Button>
            </div>

            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onNodeClick={handleNodeClick}
                onPaneClick={handlePaneClick}
                nodeTypes={nodeTypes}
                fitView
                className="bg-pentra-black"
                // Cyberpunk styling for controls + minimap via CSS classes internally handled, but we use strict dark colors
                style={{ background: '#050505' }}
            >
                <MiniMap
                    nodeColor={(n: any) => {
                        if (n.data?.isCompromised) return '#ff003c';
                        if (n.data?.type === 'asset') return '#00eaff';
                        if (n.data?.type === 'vulnerability') return '#ff5a1f';
                        return '#2b2b2b';
                    }}
                    style={{ backgroundColor: '#0f0f0f', border: '1px solid #2b2b2b', borderRadius: 0 }}
                    maskColor="rgba(5, 5, 5, 0.7)"
                />
                <Controls
                    style={{ display: 'flex', flexDirection: 'column', backgroundColor: '#0f0f0f', border: '1px solid #2b2b2b', borderRadius: 0, padding: 0 }}
                    showInteractive={false}
                />
                <Background gap={30} size={1} color="#2b2b2b" />
            </ReactFlow>

            {/* Node Details Overlay Panel */}
            {selectedNode && (
                <Card className="absolute top-4 right-4 z-10 w-80 bg-pentra-surface/95 backdrop-blur-md animate-in slide-in-from-right-4 fade-in">
                    <CardHeader className="flex flex-row items-center justify-between">
                        <CardTitle className="text-white">NODE INTELLIGENCE</CardTitle>
                        <Badge variant="outline" className="border-pentra-border-strong text-pentra-text-muted">
                            {selectedNode.data.type}
                        </Badge>
                    </CardHeader>
                    <CardContent className="space-y-4 font-mono text-sm leading-relaxed p-4">
                        <div>
                            <div className="text-[10px] text-pentra-text-dim uppercase tracking-widest mb-1">IDENTIFIER</div>
                            <div className="text-pentra-cyan font-bold break-all">{selectedNode.data.label}</div>
                        </div>

                        {selectedNode.data.isCompromised && (
                            <div className="flex items-center gap-2 bg-pentra-critical/10 border border-pentra-critical p-2">
                                <Skull size={14} className="text-pentra-critical animate-pulse" />
                                <span className="text-xs text-pentra-critical tracking-widest uppercase">COMPROMISED (EXP-SUCCESS)</span>
                            </div>
                        )}

                        {selectedNode.data.type === 'vulnerability' && (
                            <>
                                <div>
                                    <div className="text-[10px] text-pentra-text-dim uppercase tracking-widest mb-1">SEVERITY</div>
                                    <SeverityBadge severity="critical" variant="default" />
                                </div>
                                <div>
                                    <div className="text-[10px] text-pentra-text-dim uppercase tracking-widest mb-1">CVSS BASE SCORE</div>
                                    <div className="text-white font-bold">9.8 (CRITICAL)</div>
                                </div>
                                <div>
                                    <div className="text-[10px] text-pentra-text-dim uppercase tracking-widest mb-1">VECTOR</div>
                                    <div className="text-pentra-text-muted text-xs break-all border border-pentra-border-strong p-2 bg-pentra-black">CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</div>
                                </div>
                                <div className="pt-2">
                                    <Button variant="default" glow className="w-full text-[10px]">VIEW EXPLOIT CHAIN ➔</Button>
                                </div>
                            </>
                        )}

                        {selectedNode.data.type === 'asset' && (
                            <>
                                <div>
                                    <div className="text-[10px] text-pentra-text-dim uppercase tracking-widest mb-1">IP ADDRESS</div>
                                    <div className="text-white">10.0.4.52</div>
                                </div>
                                <div>
                                    <div className="text-[10px] text-pentra-text-dim uppercase tracking-widest mb-1">OPEN PORTS</div>
                                    <div className="flex gap-2 text-xs">
                                        <span className="bg-pentra-black border border-pentra-border-strong px-2 py-0.5">80 (HTTP)</span>
                                        <span className="bg-pentra-black border border-pentra-border-strong px-2 py-0.5">443 (HTTPS)</span>
                                    </div>
                                </div>
                                <div className="pt-2">
                                    <Button variant="outline" className="w-full text-[10px] border-pentra-cyan text-pentra-cyan">RUN TARGETED ENUM ➔</Button>
                                </div>
                            </>
                        )}

                    </CardContent>
                </Card>
            )}
        </div>
    );
}
