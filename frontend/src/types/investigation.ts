export type EvidenceClassification = 'OBSERVED' | 'INFERRED' | 'UNKNOWN';
export type InvestigationVerdict =
  | 'LIKELY_PHISHING'
  | 'SUSPICIOUS'
  | 'INCONCLUSIVE'
  | 'NO_STRONG_INDICATORS_DETECTED'
  | 'BENIGN'
  | 'UNDER_INVESTIGATION';

export interface KeyIndicator {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  description: string;
  evidence_ids: string[];
}

export interface DetectionResult {
  verdict: InvestigationVerdict;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
  plain_explanation: string;
  key_indicators: KeyIndicator[];
  mitigating_factors: string[];
  limitations: string[];
}

export interface EvidenceItem {
  id: string;
  investigation_id: string;
  evidence_type: string;
  observed_value: string;
  source_location: string;
  classification: EvidenceClassification;
  explanation: string;
  limitations?: string | null;
  confidence_level?: string | null;
  extra_data?: Record<string, any> | null;
  created_at: string;
}

export interface AuthMechanismResult {
  status: string;
  details?: string | null;
  source_header?: string | null;
}

export interface ExtractedUrl {
  url: string;
  source: string;
  display_text: string;
  is_discrepancy: boolean;
  discrepancy_description?: string | null;
  domain?: string | null;
}

export interface ExtractedAttachment {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  disposition: string;
}

export interface ExtractedDiscrepancy {
  type: string;
  display_text?: string;
  destination_url?: string;
  apparent_domain?: string;
  target_domain?: string;
  description: string;
  from_domain?: string;
  reply_to_domain?: string;
  return_path_domain?: string;
}

export interface ReceivedHop {
  hop: number;
  raw: string;
  summary: string;
}

export interface ParsedEmailMetadata {
  headers: {
    subject?: string;
    from?: string;
    to?: string;
    cc?: string;
    bcc?: string;
    reply_to?: string;
    return_path?: string;
    message_id?: string;
    date?: string;
    from_parsed?: { name?: string; address?: string };
    reply_to_parsed?: { name?: string; address?: string };
    return_path_parsed?: { name?: string; address?: string };
    to_parsed?: Array<{ name?: string; address?: string }>;
  };
  all_headers_raw: Array<{ name: string; value: string }>;
  received_chain: ReceivedHop[];
  auth_results: {
    spf: AuthMechanismResult;
    dkim: AuthMechanismResult;
    dmarc: AuthMechanismResult;
    raw_auth_headers: string[];
  };
  urls: ExtractedUrl[];
  domains: string[];
  attachments: ExtractedAttachment[];
  discrepancies: ExtractedDiscrepancy[];
  body_plain_preview?: string;
  safe_body_text_preview?: string;
  has_html?: boolean;
  parsing_warnings?: string[];
  detection_result?: DetectionResult;
}

export interface Investigation {
  id: string;
  title: string;
  filename: string;
  file_size_bytes: number;
  created_at: string;
  subject?: string | null;
  sender?: string | null;
  recipient?: string | null;
  verdict: InvestigationVerdict;
  summary_notes?: string | null;
  parsed_metadata?: ParsedEmailMetadata | null;
}

export interface InvestigationDetail extends Investigation {
  evidence_items: EvidenceItem[];
}

export interface GraphNode {
  id: string;
  type?: string;
  position: { x: number; y: number };
  data: {
    label: string;
    category: string;
    [key: string]: any;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  animated?: boolean;
  type?: string;
  data?: {
    style_type?: string;
    [key: string]: any;
  };
}

export interface EvidenceGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ReconstructionEvent {
  step: number;
  stage: string;
  category: 'OBSERVED' | 'INFERRED' | 'UNKNOWN / UNVERIFIABLE';
  timestamp: string;
  title: string;
  description: string;
  evidence_reference: string;
  is_hypothetical: boolean;
  status: string;
}

export interface EvidenceGap {
  gap_id: string;
  category: string;
  title: string;
  status: string;
  why_needed: string;
  collection_source: string;
  impact_on_conclusion: string;
}

export interface ForensicReport {
  report_metadata: {
    platform: string;
    platform_version: string;
    generated_at: string;
    report_id: string;
    investigation_id: string;
    case_title: string;
  };
  executive_summary: {
    original_filename: string;
    file_size_bytes: number;
    subject?: string;
    sender?: string;
    recipient?: string;
    verdict: string;
    verdict_summary?: string;
  };
  authentication_summary: {
    spf?: AuthMechanismResult;
    dkim?: AuthMechanismResult;
    dmarc?: AuthMechanismResult;
    raw_auth_headers?: string[];
  };
  indicators: {
    extracted_urls_count: number;
    extracted_urls: ExtractedUrl[];
    extracted_domains_count: number;
    extracted_domains: string[];
    attachments_count: number;
    attachments: ExtractedAttachment[];
    detected_discrepancies: ExtractedDiscrepancy[];
  };
  classified_evidence_items: EvidenceItem[];
  attack_sequence_reconstruction: ReconstructionEvent[];
  evidence_gaps_and_recommendations: EvidenceGap[];
  forensic_methodology_and_limitations: {
    core_principle: string;
    disclaimer: string;
    recommended_next_steps: string[];
  };
}
