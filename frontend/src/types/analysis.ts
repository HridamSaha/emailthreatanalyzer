export type Classification = "safe" | "suspicious" | "malicious" | "manual_review";

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: string;
  evidence: string;
  explanation: string;
  score_contribution: number;
  suggested_response: string;
  evidence_kind: string;
  category?: string;
}

export interface Indicator {
  indicator_type: string;
  value: string;
  provenance: string;
  verification_status: string;
  notes?: string;
}

export interface AnalysisResult {
  id: string;
  analysis_type: string;
  original_filename?: string | null;
  input_hash?: string | null;
  created_at?: string | null;
  classification: Classification;
  risk_score: number;
  severity: string;
  status?: string;
  summary: string;
  evidence_strength: string;
  explanation?: string;
  recommended_action: string;
  limitations?: string[];
  parser_warnings?: string[];
  header_analysis?: Record<string, unknown>;
  body_analysis?: { text?: string; html_present?: boolean; note?: string };
  url_analysis?: Record<string, unknown>[];
  attachment_analysis?: Record<string, unknown>[];
  findings?: Finding[];
  indicators?: Indicator[];
  ml?: Record<string, unknown>;
  integrations?: Record<string, unknown>;
  app_version?: string;
}

export interface HistoryItem {
  id: string;
  analysis_type: string;
  original_filename?: string | null;
  subject?: string | null;
  sender_domain?: string | null;
  created_at?: string | null;
  classification: Classification;
  risk_score: number;
  severity: string;
  summary: string;
}

export interface Stats {
  total: number;
  safe: number;
  suspicious: number;
  malicious: number;
  manual_review: number;
  high_risk: number;
  classification_distribution: Record<string, number>;
  recent: HistoryItem[];
  top_rules: { rule_id: string; rule_name: string; count: number }[];
  recent_domains: { domain: string; count: number }[];
  recent_hashes: string[];
  risk_trend: { date: string; avg_score: number; count: number }[];
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  enabled: boolean;
  logic_summary: string;
  default_score: number;
  times_triggered: number;
}
