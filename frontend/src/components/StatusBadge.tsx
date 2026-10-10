import React from 'react';
import { AlertTriangle, CheckCircle2, HelpCircle, Shield, Eye, Cpu } from 'lucide-react';
import type { InvestigationVerdict, EvidenceClassification } from '../types/investigation';

interface VerdictBadgeProps {
  verdict: InvestigationVerdict | string;
  size?: 'sm' | 'md';
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({ verdict, size = 'md' }) => {
  const norm = verdict.toUpperCase();
  const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-xs px-2.5 py-1 font-semibold';

  if (norm === 'LIKELY_PHISHING') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md bg-rose-500/15 text-rose-300 border border-rose-500/40 font-bold ${sizeClasses}`}>
        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-rose-400" />
        <span>LIKELY PHISHING</span>
      </span>
    );
  }

  if (norm === 'SUSPICIOUS') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/40 font-semibold ${sizeClasses}`}>
        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-amber-400" />
        <span>SUSPICIOUS</span>
      </span>
    );
  }

  if (norm === 'NO_STRONG_INDICATORS_DETECTED' || norm === 'BENIGN') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 ${sizeClasses}`}>
        <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
        <span>{norm === 'BENIGN' ? 'BENIGN' : 'NO STRONG INDICATORS'}</span>
      </span>
    );
  }

  if (norm === 'INCONCLUSIVE') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md bg-slate-500/15 text-slate-300 border border-slate-500/30 ${sizeClasses}`}>
        <HelpCircle className="w-3.5 h-3.5 flex-shrink-0 text-slate-400" />
        <span>INCONCLUSIVE</span>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md bg-slate-700/40 text-slate-300 border border-slate-600/40 ${sizeClasses}`}>
      <Shield className="w-3.5 h-3.5 flex-shrink-0" />
      <span>{norm || 'UNDER INVESTIGATION'}</span>
    </span>
  );
};

interface ClassificationBadgeProps {
  classification: EvidenceClassification | string;
}

export const ClassificationBadge: React.FC<ClassificationBadgeProps> = ({ classification }) => {
  const norm = classification.toUpperCase();

  if (norm === 'OBSERVED') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 font-medium rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
        <Eye className="w-3 h-3 flex-shrink-0" />
        <span>OBSERVED</span>
      </span>
    );
  }

  if (norm === 'INFERRED') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 font-medium rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
        <Cpu className="w-3 h-3 flex-shrink-0" />
        <span>INFERRED</span>
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 font-medium rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
      <HelpCircle className="w-3 h-3 flex-shrink-0" />
      <span>UNKNOWN</span>
    </span>
  );
};
