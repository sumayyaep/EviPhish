import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Inbox,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  PlusCircle,
  RefreshCw,
  ArrowRight,
  FileText,
  Clock,
  ExternalLink,
} from 'lucide-react';
import { api } from '../services/api';
import type { Investigation } from '../types/investigation';
import { VerdictBadge } from '../components/StatusBadge';

interface DashboardProps {
  onNavigate: (view: string, investigationId?: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getInvestigations();
      setInvestigations(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to connect to the EviPhish backend API.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let ignore = false;
    const runFetch = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getInvestigations();
        if (!ignore) setInvestigations(data);
      } catch (err: any) {
        if (!ignore) setError(err?.message || 'Failed to connect to the EviPhish backend API.');
      } finally {
        if (!ignore) setLoading(false);
      }
    };
    runFetch();
    return () => {
      ignore = true;
    };
  }, []);

  const total = investigations.length;
  const suspiciousCount = investigations.filter(
    (i) => i.verdict === 'LIKELY_PHISHING' || i.verdict === 'SUSPICIOUS'
  ).length;
  const benignCount = investigations.filter(
    (i) => i.verdict === 'NO_STRONG_INDICATORS_DETECTED' || i.verdict === 'BENIGN'
  ).length;
  const inconclusiveCount = investigations.filter((i) => i.verdict === 'INCONCLUSIVE').length;

  const recent = investigations.slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Title & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Forensic Operations Dashboard</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time evidentiary status and case telemetry
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={fetchStats}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-700/80 text-slate-300 hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50"
            title="Refresh statistics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => onNavigate('new')}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-400 text-slate-950 transition-colors shadow-md cursor-pointer"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </button>
        </div>
      </div>

      {/* Error state alert */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-rose-400" />
            <div>
              <p className="font-semibold text-rose-200">API Connection Error</p>
              <p className="mt-0.5 text-rose-300/90">{error}</p>
            </div>
          </div>
          <button
            onClick={fetchStats}
            className="px-2.5 py-1 text-xs rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-700 text-rose-200 cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Total Cases</span>
            <Inbox className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white font-mono">
            {loading ? '...' : total}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">RFC 5322 emails parsed</p>
        </div>

        <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Suspicious</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400 font-mono">
            {loading ? '...' : suspiciousCount}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Backed by deceptive indicators</p>
        </div>

        <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Benign</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400 font-mono">
            {loading ? '...' : benignCount}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Passing aligned authentication</p>
        </div>

        <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Inconclusive</span>
            <HelpCircle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400 font-mono">
            {loading ? '...' : inconclusiveCount}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Insufficient authentication records</p>
        </div>
      </div>

      {/* Core Principle Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-sky-950/40 via-[#0e1626] to-[#0e1626] border border-sky-800/40 text-xs text-sky-200/90 flex items-start gap-3">
        <ShieldAlert className="w-5 h-5 flex-shrink-0 text-sky-400 mt-0.5" />
        <div>
          <span className="font-semibold text-white">Forensic Standard: Evidence First, Conclusion Second.</span>{' '}
          Findings in EviPhish are derived strictly from observable artifacts within RFC 5322 headers and MIME payloads.
          We never hypothesize user compromise, clicked links, or malware execution without explicit secondary telemetry.
        </div>
      </div>

      {/* Recent Investigations Panel */}
      <div className="rounded-xl border border-slate-800 bg-[#0e1626] overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-white">Recent Investigations</h3>
          </div>
          {total > 0 && (
            <button
              onClick={() => onNavigate('investigations')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center gap-1 transition-colors cursor-pointer"
            >
              <span>View All ({total})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-400 text-xs">
            <RefreshCw className="w-6 h-6 animate-spin text-sky-400 mx-auto mb-2" />
            Loading forensic records...
          </div>
        ) : recent.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 text-slate-500 mx-auto flex items-center justify-center mb-3">
              <Inbox className="w-6 h-6" />
            </div>
            <h4 className="text-sm font-medium text-slate-200">No investigations logged yet</h4>
            <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
              Upload a suspicious or benign RFC 5322 (.eml) email file to initiate automated evidence extraction.
            </p>
            <button
              onClick={() => onNavigate('new')}
              className="mt-4 inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-400 text-slate-950 transition-colors cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Upload Your First .eml</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0b121f] text-slate-400 border-b border-slate-800/80 font-medium">
                <tr>
                  <th className="py-2.5 px-4">Case / Subject</th>
                  <th className="py-2.5 px-4">Sender</th>
                  <th className="py-2.5 px-4">Verdict</th>
                  <th className="py-2.5 px-4">Date</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {recent.map((inv) => (
                  <tr key={inv.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 max-w-xs truncate">
                      <div className="font-medium text-white truncate" title={inv.title}>
                        {inv.title}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5" title={inv.subject || ''}>
                        {inv.subject || 'No Subject'}
                      </div>
                    </td>
                    <td className="py-3 px-4 max-w-[200px] truncate text-slate-300">
                      <span className="font-mono text-[11px]" title={inv.sender || ''}>
                        {inv.sender || 'Unknown'}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <VerdictBadge verdict={inv.verdict} size="sm" />
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400 text-[11px]">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{new Date(inv.created_at).toLocaleDateString()}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => onNavigate('analysis', inv.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs font-medium transition-colors cursor-pointer"
                      >
                        <span>Analyze</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
