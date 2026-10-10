import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  Mail,
  Shield,
  Link as LinkIcon,
  Paperclip,
  GitBranch,
  Clock,
  HelpCircle,
  FileDown,
  RefreshCw,
  AlertTriangle,
  Copy,
  Check,
  Search,
  Hash,
  Eye,
  FileText,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  InvestigationDetail,
  EvidenceGraphData,
  ReconstructionEvent,
  EvidenceGap,
  ForensicReport,
} from '../types/investigation';
import { VerdictBadge, ClassificationBadge } from '../components/StatusBadge';
const EvidenceGraphView = React.lazy(() => import('../components/EvidenceGraphView').then(module => ({ default: module.EvidenceGraphView })));
import { DetectionResultCard } from '../components/DetectionResultCard';

interface EmailAnalysisProps {
  investigationId: string;
  onNavigate: (view: string, investigationId?: string) => void;
}

type TabType =
  | 'overview'
  | 'headers'
  | 'urls'
  | 'attachments'
  | 'evidence'
  | 'graph'
  | 'reconstruction'
  | 'gaps'
  | 'report';

export const EmailAnalysis: React.FC<EmailAnalysisProps> = ({ investigationId, onNavigate }) => {
  const [investigation, setInvestigation] = useState<InvestigationDetail | null>(null);
  const [graphData, setGraphData] = useState<EvidenceGraphData | null>(null);
  const [timeline, setTimeline] = useState<ReconstructionEvent[] | null>(null);
  const [gaps, setGaps] = useState<EvidenceGap[] | null>(null);
  const [report, setReport] = useState<ForensicReport | null>(null);

  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [headerSearch, setHeaderSearch] = useState<string>('');

  useEffect(() => {
    let ignore = false;
    const runFetch = async () => {
      setLoading(true);
      setError(null);
      try {
        const inv = await api.getInvestigation(investigationId);
        if (!ignore) setInvestigation(inv);

        const [gData, tData, gapData] = await Promise.all([
          api.getInvestigationGraph(investigationId).catch(() => null),
          api.getInvestigationReconstruction(investigationId).catch(() => null),
          api.getInvestigationGaps(investigationId).catch(() => null),
        ]);

        if (!ignore) {
          setGraphData(gData);
          setTimeline(tData);
          setGaps(gapData);
        }
      } catch (err: any) {
        if (!ignore) setError(err?.message || 'Failed to load investigation details.');
      } finally {
        if (!ignore) setLoading(false);
      }
    };

    runFetch();
    return () => {
      ignore = true;
    };
  }, [investigationId]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleDownloadReport = async () => {
    try {
      let rpt = report;
      if (!rpt) {
        rpt = await api.exportReport(investigationId);
        setReport(rpt);
      }
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rpt, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `EviPhish_Report_${investigationId.slice(0, 8)}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (err: any) {
      alert(`Report download failed: ${err?.message || 'Unknown error'}`);
    }
  };

  if (loading) {
    return (
      <div className="p-16 text-center text-slate-400 text-xs space-y-3">
        <RefreshCw className="w-7 h-7 animate-spin text-sky-400 mx-auto" />
        <p className="font-medium text-slate-300">Retrieving case artifacts and evidence relationships...</p>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="p-8 rounded-xl bg-[#0e1626] border border-slate-800 text-center max-w-lg mx-auto space-y-4">
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg inline-block">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <h3 className="text-base font-bold text-white">Investigation Not Found</h3>
        <p className="text-xs text-slate-400">{error || 'The requested investigation case does not exist.'}</p>
        <button
          onClick={() => onNavigate('investigations')}
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Investigations</span>
        </button>
      </div>
    );
  }

  const meta = investigation.parsed_metadata;
  const auth = meta?.auth_results;
  const headers = meta?.headers;
  const discrepancies = meta?.discrepancies || [];
  const urls = meta?.urls || [];
  const attachments = meta?.attachments || [];
  const domains = meta?.domains || [];

  const tabs: { id: TabType; label: string; icon: any; count?: number }[] = [
    { id: 'overview', label: 'Overview & Body', icon: Mail },
    { id: 'headers', label: 'Headers & Auth', icon: Shield },
    { id: 'urls', label: 'URLs & Domains', icon: LinkIcon, count: urls.length },
    { id: 'attachments', label: 'Attachments', icon: Paperclip, count: attachments.length },
    { id: 'evidence', label: 'Classified Evidence', icon: Eye, count: investigation.evidence_items.length },
    { id: 'graph', label: 'Evidence Graph', icon: GitBranch },
    { id: 'reconstruction', label: 'Reconstruction', icon: Clock },
    { id: 'gaps', label: 'Evidence Gaps', icon: HelpCircle, count: gaps?.length },
    { id: 'report', label: 'Export Report', icon: FileDown },
  ];

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('investigations')}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
            title="Back to Investigations"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight truncate max-w-lg" title={investigation.title}>
                {investigation.title}
              </h2>
              <VerdictBadge verdict={investigation.verdict} size="sm" />
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">
              Case ID: {investigation.id} • File: {investigation.filename}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadReport}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-sky-300 border border-sky-500/30 transition-colors cursor-pointer"
          >
            <FileDown className="w-3.5 h-3.5" />
            <span>Download Report</span>
          </button>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center gap-1 overflow-x-auto pb-1 border-b border-slate-800 scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-t-lg text-xs font-medium whitespace-nowrap transition-all border-b-2 cursor-pointer ${
                isActive
                  ? 'border-sky-400 text-sky-300 bg-sky-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {typeof tab.count === 'number' && (
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                    isActive ? 'bg-sky-500/20 text-sky-200' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Overview & Safe Body */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Detection Result Card */}
          <DetectionResultCard
            detection={meta?.detection_result}
            fallbackVerdict={investigation.verdict}
            fallbackExplanation={investigation.summary_notes}
            onNavigateTab={setActiveTab}
          />

          {/* Metadata Card */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-sky-400" />
                <span>Envelope & Headers Summary</span>
              </h3>
              <dl className="text-xs space-y-2">
                <div>
                  <dt className="text-slate-500 text-[11px]">Subject</dt>
                  <dd className="font-semibold text-white mt-0.5">{investigation.subject || 'Not specified'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500 text-[11px]">From (Sender)</dt>
                  <dd className="font-mono text-slate-200 mt-0.5">{investigation.sender || 'Unknown'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500 text-[11px]">To (Recipient)</dt>
                  <dd className="font-mono text-slate-200 mt-0.5">{investigation.recipient || 'Unknown'}</dd>
                </div>
                {headers?.reply_to && (
                  <div>
                    <dt className="text-slate-500 text-[11px]">Reply-To</dt>
                    <dd className="font-mono text-slate-300 mt-0.5">{headers.reply_to}</dd>
                  </div>
                )}
                {headers?.return_path && (
                  <div>
                    <dt className="text-slate-500 text-[11px]">Return-Path</dt>
                    <dd className="font-mono text-slate-300 mt-0.5">{headers.return_path}</dd>
                  </div>
                )}
                <div>
                  <dt className="text-slate-500 text-[11px]">Origination Date</dt>
                  <dd className="text-slate-300 mt-0.5">{headers?.date || 'Not specified in header'}</dd>
                </div>
              </dl>
            </div>

            <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3 flex flex-col justify-between">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-sky-400" />
                  <span>File & Extraction Stats</span>
                </h3>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 space-y-2">
                <div className="flex justify-between">
                  <span>File Name:</span>
                  <span className="font-mono text-slate-300 truncate max-w-[200px]" title={investigation.filename}>
                    {investigation.filename}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>File Size:</span>
                  <span className="font-mono text-slate-300">{(investigation.file_size_bytes / 1024).toFixed(1)} KB</span>
                </div>
                <div className="flex justify-between">
                  <span>Evidence Count:</span>
                  <span className="font-mono text-slate-300">{investigation.evidence_items.length} items</span>
                </div>
                <div className="flex justify-between">
                  <span>Extracted Domains:</span>
                  <span className="font-mono text-slate-300">{domains.length} unique</span>
                </div>
              </div>
            </div>
          </div>

          {/* Safe Body Viewer */}
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-sky-400" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Safe Body Content Preview
                </h3>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Sandboxed & Script-Stripped
              </span>
            </div>

            <p className="text-[11px] text-slate-400">
              Rendered in defensive isolation. JavaScript, iframes, and active browser handlers have been safely sanitized.
            </p>

            <div className="p-4 rounded-lg bg-[#090d16] border border-slate-800/80 font-mono text-xs text-slate-200 max-h-80 overflow-y-auto whitespace-pre-wrap leading-relaxed select-text">
              {meta?.safe_body_text_preview || meta?.body_plain_preview || 'No text body payload found.'}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Headers & Authentication */}
      {activeTab === 'headers' && (
        <div className="space-y-6">
          {/* Authentication Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* SPF */}
            <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-mono">SPF (Sender Policy)</span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    auth?.spf.status === 'PASS'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : auth?.spf.status === 'FAIL'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  }`}
                >
                  {auth?.spf.status || 'UNKNOWN'}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 break-words font-mono">
                {auth?.spf.details || 'No SPF details in headers'}
              </p>
              <p className="text-[10px] text-slate-500 pt-1 border-t border-slate-800">
                Source: {auth?.spf.source_header || 'Header not present'}
              </p>
            </div>

            {/* DKIM */}
            <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-mono">DKIM (Signature)</span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    auth?.dkim.status === 'PASS'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : auth?.dkim.status === 'FAIL'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  }`}
                >
                  {auth?.dkim.status || 'UNKNOWN'}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 break-words font-mono">
                {auth?.dkim.details || 'No cryptographic signature header'}
              </p>
              <p className="text-[10px] text-slate-500 pt-1 border-t border-slate-800">
                Source: {auth?.dkim.source_header || 'Header not present'}
              </p>
            </div>

            {/* DMARC */}
            <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-mono">DMARC (Alignment)</span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    auth?.dmarc.status === 'PASS'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : auth?.dmarc.status === 'FAIL'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  }`}
                >
                  {auth?.dmarc.status || 'UNKNOWN'}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 break-words font-mono">
                {auth?.dmarc.details || 'No DMARC evaluation recorded'}
              </p>
              <p className="text-[10px] text-slate-500 pt-1 border-t border-slate-800">
                Source: {auth?.dmarc.source_header || 'Header not present'}
              </p>
            </div>
          </div>

          {/* Received Relay Chain */}
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-sky-400" />
              <span>Received Relay Hops (MTA Transit Chain)</span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Ordered from final receiving perimeter (Hop 1) backwards to the originating relay.
            </p>

            {meta?.received_chain && meta.received_chain.length > 0 ? (
              <div className="space-y-2">
                {meta.received_chain.map((hop) => (
                  <div key={hop.hop} className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs">
                    <div className="flex items-center justify-between text-slate-400 mb-1">
                      <span className="font-mono text-[10px] text-sky-400 font-bold">Hop {hop.hop}</span>
                    </div>
                    <p className="font-mono text-slate-200 text-[11px] break-all">{hop.summary}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">No Received headers recorded in email file.</p>
            )}
          </div>

          {/* Raw Headers Explorer */}
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Preserved Header Registry ({meta?.all_headers_raw?.length || 0})
              </h3>
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter headers..."
                  value={headerSearch}
                  onChange={(e) => setHeaderSearch(e.target.value)}
                  className="pl-8 pr-3 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/60 rounded-lg border border-slate-800 bg-[#090d16]">
              {meta?.all_headers_raw
                ?.filter((h) =>
                  headerSearch
                    ? h.name.toLowerCase().includes(headerSearch.toLowerCase()) ||
                      h.value.toLowerCase().includes(headerSearch.toLowerCase())
                    : true
                )
                .map((h, idx) => (
                  <div key={idx} className="p-2.5 text-xs hover:bg-slate-800/30 transition-colors">
                    <span className="font-mono font-bold text-sky-400">{h.name}: </span>
                    <span className="font-mono text-slate-300 break-all select-text">{h.value}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: URLs & Domains */}
      {activeTab === 'urls' && (
        <div className="space-y-6">
          {/* Deceptive Discrepancies Alerts */}
          {discrepancies.length > 0 && (
            <div className="space-y-2">
              {discrepancies.map((disc, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-200 text-xs flex items-start gap-3"
                >
                  <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400 mt-0.5" />
                  <div>
                    <h4 className="font-bold text-rose-300 text-xs uppercase tracking-wide">
                      {disc.type.replace(/_/g, ' ')}
                    </h4>
                    <p className="mt-1 text-slate-200 font-mono text-[11px]">{disc.description}</p>
                    {disc.display_text && disc.destination_url && (
                      <div className="mt-2 p-2 rounded bg-slate-950/60 border border-rose-500/20 font-mono text-[10px] space-y-0.5">
                        <p className="text-slate-400">Anchor Display: <span className="text-amber-300">{disc.display_text}</span></p>
                        <p className="text-slate-400">Destination Href: <span className="text-rose-300">{disc.destination_url}</span></p>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* URLs Table */}
          <div className="rounded-xl border border-slate-800 bg-[#0e1626] overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
                Extracted Hyperlinks ({urls.length})
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Analyzed statically without automated outbound HTTP requests.
              </p>
            </div>

            {urls.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">No hyperlinks detected in email body.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0b121f] text-slate-400 border-b border-slate-800 font-medium">
                    <tr>
                      <th className="py-2.5 px-4">Destination URL</th>
                      <th className="py-2.5 px-4">Anchor Text</th>
                      <th className="py-2.5 px-4">Domain</th>
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4 text-right">Copy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {urls.map((u, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3 px-4 max-w-sm truncate font-mono text-[11px]" title={u.url}>
                          {u.url}
                        </td>
                        <td className="py-3 px-4 max-w-xs truncate text-[11px]" title={u.display_text}>
                          {u.display_text}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px] text-sky-400">
                          {u.domain || 'N/A'}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {u.is_discrepancy ? (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                              MISMATCH
                            </span>
                          ) : (
                            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                              STATIC
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right whitespace-nowrap">
                          <button
                            onClick={() => copyToClipboard(u.url, `url_${idx}`)}
                            className="p-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors cursor-pointer"
                            title="Copy safe URL"
                          >
                            {copiedText === `url_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Domains Registry */}
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Correlated Domains Registry ({domains.length})
            </h3>
            <div className="flex flex-wrap gap-2">
              {domains.map((dom, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs text-sky-300"
                >
                  <span>{dom}</span>
                  <button
                    onClick={() => copyToClipboard(dom, `dom_${idx}`)}
                    className="text-slate-500 hover:text-slate-300 cursor-pointer"
                    title="Copy domain"
                  >
                    {copiedText === `dom_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Attachments */}
      {activeTab === 'attachments' && (
        <div className="rounded-xl border border-slate-800 bg-[#0e1626] overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
              Attachments ({attachments.length})
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Extracted metadata and cryptographic hashes without executing or opening binaries.
            </p>
          </div>

          {attachments.length === 0 ? (
            <div className="p-10 text-center text-xs text-slate-400">No attachments found in this email message.</div>
          ) : (
            <div className="divide-y divide-slate-800/60">
              {attachments.map((att, idx) => (
                <div key={idx} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 mt-0.5">
                      <Paperclip className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-mono font-semibold text-white text-xs">{att.filename}</h4>
                      <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-1">
                        <span>Type: {att.content_type}</span>
                        <span>•</span>
                        <span>Size: {(att.size_bytes / 1024).toFixed(1)} KB ({att.size_bytes} bytes)</span>
                        <span>•</span>
                        <span>Disposition: {att.disposition}</span>
                      </div>
                      <div className="mt-2 flex items-center gap-2 bg-slate-900 border border-slate-800 px-2.5 py-1 rounded font-mono text-[10px] text-slate-300">
                        <Hash className="w-3 h-3 text-slate-500" />
                        <span className="truncate">SHA256: {att.sha256}</span>
                        <button
                          onClick={() => copyToClipboard(att.sha256, `hash_${idx}`)}
                          className="text-slate-400 hover:text-slate-200 cursor-pointer ml-auto"
                          title="Copy SHA-256"
                        >
                          {copiedText === `hash_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Classified Evidence */}
      {activeTab === 'evidence' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
                Atomic Evidence Catalog ({investigation.evidence_items.length})
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Every observation is cataloged with its specific source location, classification, and defensible limitations.
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {investigation.evidence_items.map((ev) => (
              <div key={ev.id} className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-xs font-bold text-sky-400">{ev.id}</span>
                      <button
                        onClick={() => copyToClipboard(ev.id, `ev_${ev.id}`)}
                        className="text-slate-500 hover:text-sky-400 cursor-pointer transition-colors"
                        title="Copy Evidence ID"
                      >
                        {copiedText === `ev_${ev.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                    <span className="text-xs font-semibold text-white">• {ev.evidence_type}</span>
                    <ClassificationBadge classification={ev.classification} />
                  </div>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    Source: {ev.source_location}
                  </span>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80 font-mono text-xs text-slate-200 break-words">
                  {ev.observed_value}
                </div>

                <div className="text-xs text-slate-300 leading-relaxed">
                  <p>{ev.explanation}</p>
                </div>

                {ev.limitations && (
                  <div className="p-2 rounded bg-amber-500/5 border border-amber-500/20 text-[11px] text-amber-300/90">
                    <strong>Limitations:</strong> {ev.limitations}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 6: Evidence Graph */}
      {activeTab === 'graph' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
                Interactive Evidence Relationship Graph
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Visualizing verified relationships between entities, auth headers, domains, and extracted indicators.
              </p>
            </div>
          </div>

          {graphData ? (
            <React.Suspense fallback={<div className="p-16 text-center text-xs text-slate-400"><RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />Loading Graph Viewer Engine...</div>}>
              <EvidenceGraphView graphData={graphData} />
            </React.Suspense>
          ) : (
            <div className="p-16 text-center text-xs text-slate-400">Loading graph relationships...</div>
          )}
        </div>
      )}

      {/* Tab 7: Attack Sequence Reconstruction */}
      {activeTab === 'reconstruction' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
              Chronological Attack Sequence Reconstruction
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Facts directly observed in the email headers and body are strictly distinguished from unverified hypotheses.
            </p>
          </div>

          <div className="space-y-4 relative before:absolute before:inset-0 before:left-5 before:w-0.5 before:bg-slate-800">
            {timeline?.map((step) => {
              const isHypo = step.is_hypothetical;
              return (
                <div key={step.step} className="relative flex items-start gap-4 ml-2">
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold font-mono z-10 flex-shrink-0 ${
                      isHypo
                        ? 'bg-amber-500/20 border border-amber-500/50 text-amber-300'
                        : step.category === 'OBSERVED'
                        ? 'bg-sky-500/20 border border-sky-500/50 text-sky-300'
                        : 'bg-purple-500/20 border border-purple-500/50 text-purple-300'
                    }`}
                  >
                    {step.step}
                  </div>

                  <div
                    className={`flex-1 p-4 rounded-xl border text-xs space-y-2 ${
                      isHypo
                        ? 'bg-amber-500/5 border-amber-500/20 text-amber-200'
                        : 'bg-[#0e1626] border-slate-800 text-slate-200'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-xs">{step.title}</span>
                        <span
                          className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase font-semibold ${
                            isHypo
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                          }`}
                        >
                          {step.category}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono">{step.timestamp}</span>
                    </div>

                    <p className="text-slate-300 leading-relaxed text-[11px]">{step.description}</p>

                    <div className="text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/80">
                      Evidentiary Basis: {step.evidence_reference}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 8: Evidence Gaps */}
      {activeTab === 'gaps' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
              Missing-Evidence Gap Analysis ({gaps?.length || 0})
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              These items are labeled as <strong className="text-amber-400">Not Collected</strong>. They represent
              critical context required before reaching definitive attribution without speculation.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {gaps?.map((gap) => (
              <div key={gap.gap_id} className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold text-sky-400">{gap.gap_id}</span>
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    NOT COLLECTED
                  </span>
                </div>

                <h4 className="text-xs font-bold text-white">{gap.title}</h4>
                <p className="text-xs text-slate-300 leading-relaxed">{gap.why_needed}</p>

                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] space-y-1">
                  <div className="text-slate-400">
                    <strong className="text-slate-300">Collection Source:</strong> {gap.collection_source}
                  </div>
                  <div className="text-slate-400">
                    <strong className="text-slate-300">Impact on Verdict:</strong> {gap.impact_on_conclusion}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 9: Export Report */}
      {activeTab === 'report' && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-[#0e1626] border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-white">Forensic Investigation Report</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Download a defensible, machine-readable JSON forensic package for incident documentation and peer review.
                </p>
              </div>

              <button
                onClick={handleDownloadReport}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold bg-sky-500 hover:bg-sky-400 text-slate-950 transition-colors shadow-md cursor-pointer self-start sm:self-auto"
              >
                <FileDown className="w-4 h-4" />
                <span>Export Report JSON</span>
              </button>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-2">
              <span className="font-semibold text-white">Methodology & Limitations Standard:</span>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                This forensic dossier is compiled exclusively from observable artifacts contained within the submitted RFC 5322 email file.
                Inferences adhere strictly to defensible correlation rules. Post-delivery exploitation (such as malware installation or credential disclosure)
                is explicitly marked as unverified pending secondary telemetry.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
