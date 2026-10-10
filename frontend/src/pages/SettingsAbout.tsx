import React, { useState, useEffect } from 'react';
import {
  Shield,
  FileCheck,
  AlertTriangle,
  Server,
  Activity,
  CheckCircle2,
  Lock,
  Layers,
  Terminal,
} from 'lucide-react';
import { api } from '../services/api';

export const SettingsAbout: React.FC = () => {
  const [healthInfo, setHealthInfo] = useState<{ status: string; service: string; version: string } | null>(null);
  const [checking, setChecking] = useState<boolean>(true);

  const checkHealth = async () => {
    setChecking(true);
    try {
      const data = await api.getHealth();
      setHealthInfo(data);
    } catch {
      setHealthInfo(null);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    let ignore = false;
    const runCheck = async () => {
      setChecking(true);
      try {
        const data = await api.getHealth();
        if (!ignore) setHealthInfo(data);
      } catch {
        if (!ignore) setHealthInfo(null);
      } finally {
        if (!ignore) setChecking(false);
      }
    };
    runCheck();
    return () => {
      ignore = true;
    };
  }, []);

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">Methodology & System Architecture</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Defensive principles, engine limitations, and system diagnostic telemetry
        </p>
      </div>

      {/* Core Principle Card */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-sky-950/40 via-[#0e1626] to-[#0e1626] border border-sky-800/50 space-y-3">
        <div className="flex items-center gap-2.5 text-sky-400">
          <Shield className="w-5 h-5" />
          <h3 className="text-sm font-bold text-white">Core Principle: Evidence First, Conclusion Second</h3>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          In defensive email forensics, jumping to conclusions without verifiable corroboration compromises investigations.
          EviPhish strictly adheres to the rule that direct observations from headers and MIME payloads must never be conflated
          with analyst interpretations or post-delivery attack hypotheses.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-[11px]">
          <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
            <span className="font-semibold text-cyan-400 font-mono">OBSERVED</span>
            <p className="text-slate-400 mt-1">Directly extracted from immutable RFC 5322 header and body artifacts.</p>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
            <span className="font-semibold text-purple-400 font-mono">INFERRED</span>
            <p className="text-slate-400 mt-1">Derived from cross-referencing indicators (e.g., anchor text vs href mismatch).</p>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
            <span className="font-semibold text-amber-400 font-mono">UNKNOWN</span>
            <p className="text-slate-400 mt-1">Missing authentication or telemetry. Never defaulted to pass or fail.</p>
          </div>
        </div>
      </div>

      {/* Architecture Overview */}
      <div className="p-5 rounded-xl bg-[#0e1626] border border-slate-800 space-y-4">
        <div className="flex items-center gap-2 text-white font-bold text-xs uppercase tracking-wider">
          <Layers className="w-4 h-4 text-sky-400" />
          <span>Technical Architecture</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="space-y-1.5 p-3 rounded-lg bg-slate-900 border border-slate-800">
            <h4 className="font-semibold text-sky-300 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              <span>Standard Library Parser</span>
            </h4>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Uses Python’s standard-library <code className="text-slate-200 font-mono">email.policy.default</code> parser.
              Does not rely on third-party opaque black-box binaries.
            </p>
          </div>

          <div className="space-y-1.5 p-3 rounded-lg bg-slate-900 border border-slate-800">
            <h4 className="font-semibold text-sky-300 flex items-center gap-1.5">
              <FileCheck className="w-3.5 h-3.5" />
              <span>SQLite Evidentiary Store</span>
            </h4>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Persists forensic cases and atomic evidence items via SQLAlchemy ORM with cascade safety and deterministic IDs.
            </p>
          </div>

          <div className="space-y-1.5 p-3 rounded-lg bg-slate-900 border border-slate-800">
            <h4 className="font-semibold text-sky-300 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5" />
              <span>React Flow Evidence Map</span>
            </h4>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Visualizes relationships strictly backed by email artifacts: sender, recipient, domains, URLs, and auth nodes.
            </p>
          </div>

          <div className="space-y-1.5 p-3 rounded-lg bg-slate-900 border border-slate-800">
            <h4 className="font-semibold text-sky-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              <span>Defensive Sandboxing</span>
            </h4>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Attachments are hashed (SHA-256) and inspected purely as metadata. No attachments are ever executed or detonated.
            </p>
          </div>
        </div>
      </div>

      {/* Limitations & Caveats */}
      <div className="p-5 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3">
        <div className="flex items-center gap-2 text-amber-400 font-bold text-xs uppercase tracking-wider">
          <AlertTriangle className="w-4 h-4" />
          <span>Forensic Limitations & Operational Scope</span>
        </div>

        <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside leading-relaxed">
          <li>
            <strong className="text-white">Zero Active Network Probing:</strong> EviPhish intentionally does not query live DNS or fetch remote HTTP URLs. In active cyber investigations, live lookups leak analyst IP telemetry and may alert adversaries that their campaign was detected.
          </li>
          <li>
            <strong className="text-white">Static Boundary:</strong> An email is an ingress vector. Concluding whether a victim was actually compromised requires correlating with web proxy logs and EDR endpoint process trees.
          </li>
          <li>
            <strong className="text-white">Environment Security:</strong> This initial application is intended for single-user local development. Production deployment requires dedicated authentication, TLS termination, and role-based access control.
          </li>
        </ul>
      </div>

      {/* Diagnostic Health Card */}
      <div className="p-5 rounded-xl bg-[#0e1626] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            <h4 className="text-xs font-bold text-white uppercase tracking-wider">Backend Service Status</h4>
          </div>
          <p className="text-[11px] text-slate-400">FastAPI backend health and version information</p>
        </div>

        <div className="flex items-center gap-3">
          {checking ? (
            <span className="text-xs text-slate-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-slate-500 animate-pulse" />
              Checking...
            </span>
          ) : healthInfo ? (
            <div className="text-right">
              <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-semibold">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{healthInfo.status.toUpperCase()}</span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono mt-0.5">{healthInfo.service} v{healthInfo.version}</p>
            </div>
          ) : (
            <span className="text-xs text-rose-400 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              Offline
            </span>
          )}

          <button
            onClick={checkHealth}
            disabled={checking}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 cursor-pointer disabled:opacity-50"
          >
            Recheck
          </button>
        </div>
      </div>
    </div>
  );
};
