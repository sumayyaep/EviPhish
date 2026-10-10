export interface SyntaxValidation {
  is_valid_format: boolean;
  normalized_email?: string | null;
  domain?: string | null;
  error?: string | null;
}

export interface ReputationResult {
  address: string;
  syntax: SyntaxValidation;
  verdict: 'REPORTED_SUSPICIOUS' | 'NO_REPORTS_FOUND' | 'INCONCLUSIVE';
  sources_checked: string[];
  findings: string[];
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  explanation: string;
  limitations: string[];
  metadata: Record<string, any>;
}
