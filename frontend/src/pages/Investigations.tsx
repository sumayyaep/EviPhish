import React, { useEffect, useState } from 'react';
import {
  Search,
  Filter,
  Trash2,
  ExternalLink,
  RefreshCw,
  PlusCircle,
  Inbox,
  AlertTriangle,
  Clock,
  HardDrive,
} from 'lucide-react';
import { api } from '../services/api';
import type { Investigation } from '../types/investigation';
import { VerdictBadge } from '../components/StatusBadge';

interface InvestigationsProps {
  onNavigate: (view: string, investigationId?: string) => void;
}

export const Investigations: React.FC<InvestigationsProps> = ({ onNavigate }) => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [verdictFilter, setVerdictFilter] = useState<string>('');

  const [deleteModalInv, setDeleteModalInv] = useState<Investigation | null>(null);
  const [deleting, setDeleting] = useState<boolean>(false);

  const fetchInvestigations = async (q = searchQuery, v = verdictFilter) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getInvestigations({
        query: q,
        verdict: v,
      });
      setInvestigations(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch investigations list.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInvestigations(searchQuery, verdictFilter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [verdictFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchInvestigations(searchQuery, verdictFilter);
  };

  const confirmDelete = async () => {
    if (!deleteModalInv) return;
    setDeleting(true);
    try {
      await api.deleteInvestigation(deleteModalInv.id);
      setDeleteModalInv(null);
      // Re-fetch from actual API to keep synchronization reliable
      await fetchInvestigations();
    } catch (err: any) {
      alert(`Deletion failed: ${err?.message || 'Unknown error'}`);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & CTA */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Email Forensic Investigations</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Search, filter, and inspect evidentiary cases stored in the SQLite repository
          </p>
        </div>

        <button
          onClick={() => onNavigate('new')}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-400 text-slate-950 transition-colors shadow-md cursor-pointer self-start sm:self-auto"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span>New Investigation</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-[#0e1626] border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-3 shadow-sm">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="flex-1 w-full flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by case title, sender, subject, or filename..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors cursor-pointer"
          >
            Search
          </button>
        </form>

        {/* Filter & Refresh */}
        <div className="flex items-center gap-2 w-full md:w-auto justify-end">
          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-1 text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Verdict:</span>
            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              aria-label="Filter investigations by verdict"
              className="bg-transparent text-slate-200 focus:outline-none text-xs cursor-pointer font-medium"
            >
              <option value="" className="bg-slate-900 text-slate-200">All Verdicts</option>
              <option value="LIKELY_PHISHING" className="bg-slate-900 text-slate-200">Likely Phishing</option>
              <option value="SUSPICIOUS" className="bg-slate-900 text-slate-200">Suspicious</option>
              <option value="NO_STRONG_INDICATORS_DETECTED" className="bg-slate-900 text-slate-200">No Strong Indicators</option>
              <option value="INCONCLUSIVE" className="bg-slate-900 text-slate-200">Inconclusive</option>
            </select>
          </div>

          <button
            onClick={() => fetchInvestigations()}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-slate-300 hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50"
            title="Refresh list"
            aria-label="Refresh investigations list"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => fetchInvestigations()}
            className="px-2.5 py-1 text-xs rounded bg-rose-950 hover:bg-rose-900 text-rose-200 border border-rose-700 cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* Investigations Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0e1626] overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-12 text-center text-slate-400 text-xs">
            <RefreshCw className="w-6 h-6 animate-spin text-sky-400 mx-auto mb-2" />
            Fetching forensic cases from SQLite...
          </div>
        ) : investigations.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 text-slate-500 mx-auto flex items-center justify-center mb-3">
              <Inbox className="w-6 h-6" />
            </div>
            <h4 className="text-sm font-medium text-slate-200">No matching investigations found</h4>
            <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
              {searchQuery || verdictFilter
                ? 'Try clearing the search query or verdict filters.'
                : 'Upload an .eml email file to create your first forensic case.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0b121f] text-slate-400 border-b border-slate-800/80 font-medium">
                <tr>
                  <th className="py-3 px-4">Case Title & Subject</th>
                  <th className="py-3 px-4">Sender & Filename</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {investigations.map((inv) => (
                  <tr key={inv.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-4 max-w-xs truncate">
                      <div className="font-semibold text-white truncate" title={inv.title}>
                        {inv.title}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5" title={inv.subject || ''}>
                        {inv.subject || 'No Subject Header'}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 max-w-[220px] truncate">
                      <div className="font-mono text-[11px] text-slate-200 truncate" title={inv.sender || ''}>
                        {inv.sender || 'Unknown'}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5" title={inv.filename}>
                        {inv.filename}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <VerdictBadge verdict={inv.verdict} size="sm" />
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 text-[11px] font-mono">
                      <div className="flex items-center gap-1">
                        <HardDrive className="w-3 h-3 text-slate-500" />
                        <span>{(inv.file_size_bytes / 1024).toFixed(1)} KB</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 text-[11px]">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{new Date(inv.created_at).toLocaleString()}</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => onNavigate('analysis', inv.id)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs font-medium transition-colors cursor-pointer"
                          title="Open detailed forensic analysis"
                        >
                          <span>Analyze</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>

                        <button
                          onClick={() => setDeleteModalInv(inv)}
                          className="p-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-colors cursor-pointer"
                          title="Delete investigation safely"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deleteModalInv && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-[#0e1626] border border-slate-700/80 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-rose-400">
              <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30">
                <Trash2 className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-white">Delete Investigation Case?</h3>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to permanently delete{' '}
              <strong className="text-white font-mono">{deleteModalInv.title}</strong>?
            </p>

            <div className="p-3 rounded-lg bg-rose-500/5 border border-rose-500/20 text-[11px] text-rose-300 space-y-1">
              <p>• Associated atomic evidence items in SQLite will be purged.</p>
              <p>• The original stored <code className="font-mono">.eml</code> file on disk will be safely unlinked.</p>
              <p>• This action cannot be undone.</p>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setDeleteModalInv(null)}
                disabled={deleting}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                disabled={deleting}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
              >
                {deleting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>{deleting ? 'Deleting...' : 'Confirm Deletion'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
