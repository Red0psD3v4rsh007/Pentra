import React, { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import { Network, Server, ShieldAlert, Key, Skull } from 'lucide-react';
import { cn } from '@/lib/utils';
import { SeverityBadge } from '../ui/severity-badge';

export type NodeType = 'asset' | 'service' | 'vulnerability' | 'credential' | 'access';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface NodeData {
    label: string;
    type: NodeType;
    severity?: Severity;
    detail?: string;
    isCompromised?: boolean;
}

const CyberNode = memo(({ data, isConnectable }: { data: NodeData, isConnectable: boolean }) => {
    // Shape and styling based on node type
    let shapeClass = "rounded-none"; // default angular
    let Icon = Network;
    let bgClass = "bg-pentra-panel border-pentra-border";
    let iconColor = "text-pentra-text-muted";

    if (data.type === 'asset') {
        shapeClass = "rounded-full aspect-square justify-center";
        Icon = Server;
        iconColor = "text-pentra-cyan";
    } else if (data.type === 'service') {
        shapeClass = "rounded-none";
        Icon = Network;
        iconColor = "text-pentra-info";
    } else if (data.type === 'vulnerability') {
        shapeClass = "rotate-45 scale-75 justify-center"; // Diamond
        Icon = ShieldAlert;
        iconColor = "text-pentra-high";
    } else if (data.type === 'credential') {
        shapeClass = "rounded-none hexagon"; // We'll simplify hexagon to sharp square for now
        Icon = Key;
        iconColor = "text-pentra-credential";
    } else if (data.type === 'access') {
        shapeClass = "rounded-none";
        Icon = Skull;
        iconColor = "text-pentra-critical";
    }

    if (data.isCompromised) {
        bgClass = "bg-pentra-critical/10 border-pentra-critical shadow-[0_0_15px_rgba(255,0,60,0.3)]";
        iconColor = "text-pentra-critical";
    }

    return (
        <div className={cn(
            "flex flex-col items-center justify-center p-3 border-2 transition-all min-w-[40px] min-h-[40px]",
            bgClass,
            shapeClass
        )}>
            <Handle type="target" position={Position.Top} isConnectable={isConnectable} className="opacity-0" />

            <div className={cn("flex flex-col items-center", data.type === 'vulnerability' && "-rotate-45")}>
                <Icon size={18} className={cn(iconColor, data.isCompromised && "animate-pulse")} />

                {/* Only show label on non-diamond shapes for layout reasons, or show outside */}
                {data.type !== 'vulnerability' && data.type !== 'asset' && (
                    <div className="mt-2 text-[10px] font-mono font-bold uppercase tracking-wider text-white whitespace-nowrap">
                        {data.label}
                    </div>
                )}
            </div>

            <Handle type="source" position={Position.Bottom} id="a" isConnectable={isConnectable} className="opacity-0" />
            <Handle type="source" position={Position.Right} id="b" isConnectable={isConnectable} className="opacity-0" />
            <Handle type="source" position={Position.Left} id="c" isConnectable={isConnectable} className="opacity-0" />
        </div>
    );
});

CyberNode.displayName = 'CyberNode';

export default CyberNode;
