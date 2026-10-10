import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  ArrowRight,
  Info,
  GitBranch,
  Shield,
  FileDown,
} from 'lucide-react';
import type { DetectionResult, InvestigationVerdict } from '../types/investigation';

interface DetectionResultCardProps {
  detection?: DetectionResult;
  fallbackVerdict: InvestigationVerdict | string;
  fallbackExplanation?: string | null;
  onNavigateTab: (tab: any) => void;
}

export const DetectionResultCard: React.FC<DetectionResultCardProps> = ({
  detection,
  fallbackVerdict,
  fallbackExplanation,
  onNavigateTab,
}) => {
  const verdict = (detection?.verdict || fallbackVerdict || 'INCONCLUSIVE').toUpperCase();
  const explanation = detection?.plain_explanation || fallbackExplanation || 'No plain-language explanation generated.';
  const confidence = detection?.confidence || 'MEDIUM';
  const score = typeof detection?.score === 'number' ? detection.score : null;
  const indicators = detection?.key_indicators || [];
  const limitations = detection?.limitations || [];
  const mitigating = detection?.mitigating_factors || [];

  const getTheme = () => {
    switch (verdict) {
      case 'LIKELY_PHISHING':
        return {
          cardBg: 'bg-gradient-to-br from-rose-950/50 via-[#0e1626] to-[#0e1626]',
          borderColor: 'border-rose-500/50 shadow-rose-950/40 shadow-lg',
          badgeBg: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <AlertOctagon className="w-6 h-6 text-rose-400" />,
          title: 'AUTOMATIC VERDICT: LIKELY PHISHING',
          accent: 'text-rose-400',
          barColor: 'bg-rose-500',
        };
      case 'SUSPICIOUS':
        return {
          cardBg: 'bg-gradient-to-br from-amber-950/50 via-[#0e1626] to-[#0e1626]',
          borderColor: 'border-amber-500/50 shadow-amber-950/40 shadow-lg',
          badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
          title: 'AUTOMATIC VERDICT: SUSPICIOUS EMAIL',
          accent: 'text-amber-400',
          barColor: 'bg-amber-500',
        };
      case 'NO_STRONG_INDICATORS_DETECTED':
      case 'BENIGN':
        return {
          cardBg: 'bg-gradient-to-br from-emerald-950/40 via-[#0e1626] to-[#0e1626]',
          borderColor: 'border-emerald-500/50 shadow-emerald-950/40 shadow-lg',
          badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
          icon: <ShieldCheck className="w-6 h-6 text-emerald-400" />,
          title: 'AUTOMATIC VERDICT: NO STRONG INDICATORS DETECTED',
          accent: 'text-emerald-400',
          barColor: 'bg-emerald-500',
        };
      default:
        return {
          cardBg: 'bg-gradient-to-br from-slate-900 via-[#0e1626] to-[#0e1626]',
          borderColor: 'border-slate-700 shadow-sm',
          badgeBg: 'bg-slate-800 text-slate-300 border-slate-700',
          icon: <HelpCircle className="w-6 h-6 text-slate-400" />,
          title: 'AUTOMATIC VERDICT: INCONCLUSIVE',
          accent: 'text-slate-400',
          barColor: 'bg-slate-500',
        };
    }
  };

  const theme = getTheme();

  return (
    <div className={`p-5 sm:p-6 rounded-2xl border ${theme.cardBg} ${theme.borderColor} space-y-5 transition-all`}>
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex items-start sm:items-center gap-3.5">
          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 shadow-inner">
            {theme.icon}
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className={`text-base font-extrabold tracking-wide ${theme.accent}`}>
                {theme.title}
              </h3>
              <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${theme.badgeBg}`}>
                Confidence: {confidence}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Evaluated automatically upon upload by the EviPhish forensic detection engine
            </p>
          </div>
        </div>

        {/* Score Meter */}
        {score !== null && (
          <div className="flex items-center gap-3 bg-slate-950/80 px-3.5 py-2 rounded-xl border border-slate-800 self-start md:self-auto">
            <div>
              <div className="text-[10px] text-slate-400 uppercase font-mono tracking-wider">Threat Score</div>
              <div className="text-base font-mono font-bold text-white leading-none mt-0.5">
                {score} <span className="text-slate-500 text-xs font-normal">/ 100</span>
              </div>
            </div>
            <div className="w-20 bg-slate-800 h-2 rounded-full overflow-hidden">
              <div className={`h-full ${theme.barColor}`} style={{ width: `${Math.max(5, score)}%` }} />
            </div>
          </div>
        )}
      </div>

      {/* Plain Language Explanation */}
      <div className="space-y-1.5">
        <div className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
          <Info className="w-3.5 h-3.5 text-sky-400" />
          <span>Automated Assessment Explanation</span>
        </div>
        <p className="text-xs text-slate-200 leading-relaxed bg-slate-950/40 p-3.5 rounded-xl border border-slate-800/70">
          {explanation}
        </p>
      </div>

      {/* Key Indicators Section */}
      {indicators.length > 0 && (
        <div className="space-y-2.5">
          <div className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span>Key Decision Indicators ({indicators.length})</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {indicators.map((ind, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs space-y-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-white truncate">{ind.name}</span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                      ind.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        : ind.severity === 'HIGH'
                        ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                        : ind.severity === 'MEDIUM'
                        ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                        : 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
                    }`}
                  >
                    {ind.severity}
                  </span>
                </div>

                <p className="text-slate-300 text-[11px] leading-relaxed">{ind.description}</p>

                {ind.evidence_ids && ind.evidence_ids.length > 0 && (
                  <div className="flex items-center gap-1.5 pt-1 border-t border-slate-800/60 text-[10px]">
                    <span className="text-slate-500 font-mono">Evidence Basis:</span>
                    <div className="flex flex-wrap gap-1">
                      {ind.evidence_ids.map((eid) => (
                        <button
                          key={eid}
                          onClick={() => onNavigateTab('evidence')}
                          className="font-mono text-sky-400 bg-sky-950/60 hover:bg-sky-900/80 px-1.5 py-0.2 rounded border border-sky-800/50 cursor-pointer transition-colors"
                          title="View evidence item"
                        >
                          {eid}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Mitigating Factors (if any) */}
      {mitigating.length > 0 && (
        <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-xs text-emerald-200 space-y-1">
          <div className="font-semibold text-emerald-300 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Mitigating Authentication Factors</span>
          </div>
          <ul className="list-disc list-inside text-[11px] text-emerald-300/90 space-y-0.5">
            {mitigating.map((m, idx) => (
              <li key={idx}>{m}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Confidence & Stated Limitations */}
      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-[11px] text-slate-400 space-y-1.5">
        <span className="font-semibold text-slate-300 flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-sky-400" />
          <span>Forensic Scope & Defensive Limitations:</span>
        </span>
        <ul className="list-disc list-inside text-slate-400 space-y-0.5 leading-relaxed">
          {limitations.map((lim, idx) => (
            <li key={idx}>{lim}</li>
          ))}
        </ul>
      </div>

      {/* Quick Action Navigation Buttons to Full Investigation */}
      <div className="pt-2 flex flex-wrap items-center gap-2 border-t border-slate-800/80">
        <span className="text-xs font-semibold text-slate-400 mr-1">Deep Forensics:</span>
        <button
          onClick={() => onNavigateTab('graph')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-sky-300 border border-sky-500/30 transition-colors cursor-pointer"
        >
          <GitBranch className="w-3.5 h-3.5" />
          <span>Interactive Evidence Graph</span>
          <ArrowRight className="w-3 h-3 text-sky-400" />
        </button>

        <button
          onClick={() => onNavigateTab('evidence')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
        >
          <span>All Evidence Items</span>
          <ArrowRight className="w-3 h-3 text-slate-400" />
        </button>

        <button
          onClick={() => onNavigateTab('headers')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
        >
          <span>Headers & Transit</span>
          <ArrowRight className="w-3 h-3 text-slate-400" />
        </button>

        <button
          onClick={() => onNavigateTab('report')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
        >
          <FileDown className="w-3.5 h-3.5" />
          <span>Export Forensic Package</span>
        </button>
      </div>
    </div>
  );
};
