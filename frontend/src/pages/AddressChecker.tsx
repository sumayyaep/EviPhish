import React, { useState } from 'react';
import { Search, ShieldAlert, ShieldCheck, HelpCircle, AlertTriangle, Loader2 } from 'lucide-react';
import { api } from '../services/api';
import type { ReputationResult } from '../types/reputation';

export const AddressChecker: React.FC = () => {
  const [email, setEmail] = useState('');
  const [consent, setConsent] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ReputationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await api.checkReputation(email, consent);
      setResult(res);
    } catch (err: any) {
      setError(err?.message || 'An error occurred during reputation checking.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">Email Address Checker</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Validate email syntax and optionally query EmailRep for known reputation (requires explicit consent).
        </p>
      </div>

      {/* Info Notice */}
      <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 text-xs text-slate-300 space-y-2 shadow-sm">
        <div className="flex items-center gap-2 text-amber-400 font-semibold">
          <AlertTriangle className="w-4 h-4" />
          <span>Important Context</span>
        </div>
        <ul className="text-slate-400 text-[11px] space-y-1 list-disc list-inside">
          <li>Checking an email address here is <strong>completely separate</strong> from analyzing an .eml message file.</li>
          <li>Address-only checks cannot determine whether an email message is a phishing attempt.</li>
          <li>A reported address may also be spoofed or compromised. Reputation does not prove identity.</li>
          <li>We do not infer phishing merely from free email providers (e.g., Gmail/Outlook) or missing reputation data.</li>
        </ul>
      </div>

      {/* Form */}
      <form onSubmit={handleCheck} className="p-6 rounded-xl bg-[#0b121f] border border-slate-800 space-y-5">
        <div className="space-y-1.5">
          <label htmlFor="email" className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
            Email Address
          </label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              id="email"
              type="text"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="e.g., suspect@example.com"
              className="w-full pl-10 pr-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors disabled:opacity-50"
              disabled={isLoading}
            />
          </div>
        </div>

        <div className="flex items-start gap-2">
          <input
            id="consent"
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            className="mt-0.5 w-4 h-4 rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-sky-500 focus:ring-offset-slate-900"
            disabled={isLoading}
          />
          <label htmlFor="consent" className="text-xs text-slate-300 cursor-pointer">
            I consent to sharing this email address with EmailRep.io for reputation analysis.
            <span className="block text-[10px] text-slate-500 mt-0.5">
              If unchecked, only local syntax validation will be performed. No email payloads or body contents will ever be sent.
            </span>
          </label>
        </div>

        <button
          type="submit"
          disabled={!email.trim() || isLoading}
          className={`w-full py-2.5 px-4 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 shadow-lg ${
            !email.trim() || isLoading
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/40'
              : 'bg-sky-500 hover:bg-sky-400 text-slate-950 cursor-pointer'
          }`}
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Querying...</span>
            </>
          ) : (
            <span>Check Address</span>
          )}
        </button>
      </form>

      {/* Error */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="space-y-4">
          <div className="p-5 sm:p-6 rounded-2xl border bg-gradient-to-br from-slate-900 via-[#0e1626] to-[#0e1626] border-slate-700 space-y-5">
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800/80">
              <div className="flex items-center gap-3.5">
                <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800">
                  {result.verdict === 'REPORTED_SUSPICIOUS' ? (
                    <ShieldAlert className="w-6 h-6 text-rose-400" />
                  ) : result.verdict === 'NO_REPORTS_FOUND' ? (
                    <ShieldCheck className="w-6 h-6 text-emerald-400" />
                  ) : (
                    <HelpCircle className="w-6 h-6 text-slate-400" />
                  )}
                </div>
                <div>
                  <h3 className="text-base font-extrabold tracking-wide text-white">
                    {result.verdict.replace(/_/g, ' ')}
                  </h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border bg-slate-800 border-slate-700 text-slate-300">
                      Confidence: {result.confidence}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="text-xs font-semibold text-white uppercase tracking-wider">Explanation</div>
              <p className="text-xs text-slate-200 leading-relaxed bg-slate-950/40 p-3.5 rounded-xl border border-slate-800/70">
                {result.explanation}
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs space-y-2">
                <span className="font-semibold text-white">Syntax & Formatting</span>
                <div className="text-[11px] text-slate-300 space-y-1 mt-1 font-mono">
                  <div>Valid Format: {result.syntax.is_valid_format ? <span className="text-emerald-400">Yes</span> : <span className="text-rose-400">No</span>}</div>
                  {result.syntax.normalized_email && <div>Normalized: {result.syntax.normalized_email}</div>}
                  {result.syntax.domain && <div>Domain: {result.syntax.domain}</div>}
                  {result.syntax.error && <div className="text-rose-400">{result.syntax.error}</div>}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs space-y-2">
                <span className="font-semibold text-white">Sources Checked</span>
                {result.sources_checked.length > 0 ? (
                  <ul className="list-disc list-inside text-[11px] text-slate-300 mt-1">
                    {result.sources_checked.map((src, idx) => (
                      <li key={idx}>{src}</li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-[11px] text-slate-500 mt-1 font-mono">No external sources queried.</div>
                )}
              </div>
            </div>

            {result.findings.length > 0 && (
              <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-500/30 text-xs space-y-2">
                <span className="font-semibold text-rose-300">Source-Backed Findings</span>
                <ul className="list-disc list-inside text-[11px] text-rose-200 mt-1">
                  {result.findings.map((f, idx) => (
                    <li key={idx} className="font-mono">{f}</li>
                  ))}
                </ul>
              </div>
            )}

            {result.limitations.length > 0 && (
              <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-[11px] text-slate-400 space-y-1.5">
                <span className="font-semibold text-slate-300">Limitations & Next Steps:</span>
                <ul className="list-disc list-inside space-y-0.5 leading-relaxed">
                  {result.limitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
