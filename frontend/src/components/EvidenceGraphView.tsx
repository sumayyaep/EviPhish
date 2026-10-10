import React, { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
  type NodeProps,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Mail,
  User,
  Globe,
  Link as LinkIcon,
  Paperclip,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
} from 'lucide-react';
import type { EvidenceGraphData } from '../types/investigation';

interface EvidenceGraphViewProps {
  graphData: EvidenceGraphData;
}

// Custom Node Component for forensic entities
const ForensicNode: React.FC<NodeProps> = ({ data }) => {
  const category = (data.category as string) || 'DEFAULT';
  const label = (data.label as string) || '';

  const getStyle = () => {
    switch (category) {
      case 'EMAIL':
        return {
          bg: 'bg-sky-950/80 border-sky-500/50 text-sky-200',
          icon: <Mail className="w-4 h-4 text-sky-400" />,
          tag: 'EMAIL ROOT',
        };
      case 'SENDER':
        return {
          bg: 'bg-indigo-950/80 border-indigo-500/50 text-indigo-200',
          icon: <User className="w-4 h-4 text-indigo-400" />,
          tag: 'FROM SENDER',
        };
      case 'RECIPIENT':
        return {
          bg: 'bg-slate-900 border-slate-700 text-slate-200',
          icon: <User className="w-4 h-4 text-slate-400" />,
          tag: 'RECIPIENT',
        };
      case 'DOMAIN':
        return {
          bg: 'bg-purple-950/80 border-purple-500/50 text-purple-200',
          icon: <Globe className="w-4 h-4 text-purple-400" />,
          tag: 'DOMAIN',
        };
      case 'AUTH':
        const status = (data.status as string) || '';
        if (status === 'PASS') {
          return {
            bg: 'bg-emerald-950/80 border-emerald-500/50 text-emerald-200',
            icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
            tag: 'AUTH PASS',
          };
        }
        if (status === 'FAIL') {
          return {
            bg: 'bg-rose-950/80 border-rose-500/50 text-rose-200',
            icon: <ShieldAlert className="w-4 h-4 text-rose-400" />,
            tag: 'AUTH FAIL',
          };
        }
        return {
          bg: 'bg-amber-950/80 border-amber-500/50 text-amber-200',
          icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
          tag: 'AUTH UNKNOWN',
        };
      case 'URL':
        return {
          bg: 'bg-cyan-950/80 border-cyan-500/50 text-cyan-200',
          icon: <LinkIcon className="w-4 h-4 text-cyan-400" />,
          tag: 'BODY URL',
        };
      case 'ATTACHMENT':
        return {
          bg: 'bg-amber-950/80 border-amber-500/50 text-amber-200',
          icon: <Paperclip className="w-4 h-4 text-amber-400" />,
          tag: 'ATTACHMENT',
        };
      case 'ALERT':
        return {
          bg: 'bg-rose-950/90 border-rose-500 text-rose-200 shadow-lg shadow-rose-950/50',
          icon: <AlertTriangle className="w-4 h-4 text-rose-400" />,
          tag: 'DECEPTIVE MISMATCH',
        };
      default:
        return {
          bg: 'bg-slate-900 border-slate-700 text-slate-200',
          icon: <Mail className="w-4 h-4 text-slate-400" />,
          tag: 'ENTITY',
        };
    }
  };

  const style = getStyle();

  return (
    <div className={`px-3 py-2 rounded-xl border shadow-md min-w-[170px] max-w-[240px] text-xs backdrop-blur-sm ${style.bg}`}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-slate-400" />
      <div className="flex items-center gap-1.5 mb-1">
        {style.icon}
        <span className="text-[9px] font-mono uppercase tracking-wider opacity-80">{style.tag}</span>
      </div>
      <div className="font-semibold truncate text-[11px]" title={label}>
        {label}
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-slate-400" />
    </div>
  );
};

export const EvidenceGraphView: React.FC<EvidenceGraphViewProps> = ({ graphData }) => {
  const nodeTypes = useMemo(() => ({ custom: ForensicNode }), []);

  const rfNodes: Node[] = useMemo(() => {
    return graphData.nodes.map((n) => ({
      id: n.id,
      type: 'custom',
      position: n.position,
      data: n.data,
    }));
  }, [graphData.nodes]);

  const rfEdges: Edge[] = useMemo(() => {
    return graphData.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: e.animated,
      style: {
        stroke: e.animated ? '#f43f5e' : '#38bdf8',
        strokeWidth: e.animated ? 2 : 1.5,
      },
      labelStyle: {
        fill: '#94a3b8',
        fontSize: 10,
        fontWeight: 600,
        fontFamily: 'monospace',
      },
      labelBgStyle: {
        fill: '#0f172a',
        fillOpacity: 0.9,
      },
      labelBgPadding: [4, 2] as [number, number],
      labelBgBorderRadius: 4,
    }));
  }, [graphData.edges]);

  return (
    <div className="w-full h-[580px] bg-[#090d16] rounded-xl border border-slate-800 overflow-hidden relative">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.2}
        maxZoom={1.5}
      >
        <Background color="#1e293b" gap={20} size={1} />
        <Controls className="!bg-slate-900 !border-slate-800 !text-slate-200 fill-slate-200" />
      </ReactFlow>

      <div className="absolute bottom-3 right-3 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg text-[10px] text-slate-400 font-mono pointer-events-none">
        Interactive React Flow Evidence Map
      </div>
    </div>
  );
};
