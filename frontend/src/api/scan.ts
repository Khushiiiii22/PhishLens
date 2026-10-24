// Types matching the FastAPI ScanResponse schema

export interface LexicalAnalysis {
  url_length: number;
  dot_count: number;
  hyphen_count: number;
  digit_count: number;
  special_char_count: number;
  entropy_score: number;
  has_suspicious_keywords: boolean;
  has_punycode_or_homoglyph: boolean;
  lexical_score: number;
}

export interface DomainAnalysis {
  domain_age_days: number | null;
  registrar: string | null;
  ssl_valid: boolean;
  ssl_issuer: string | null;
  dnssec_enabled: boolean;
  domain_score: number;
}

export interface BehaviorAnalysis {
  has_login_form: boolean;
  has_hidden_iframe: boolean;
  has_js_redirect: boolean;
  external_form_action: boolean;
  popup_detected: boolean;
  behavior_score: number;
  behavior_analysis_failed: boolean;
  behavior_failure_reason?: string | null;
  blocked_private_requests?: number;
}

export interface MLAnalysis {
  prediction: string;
  confidence: number;
  model_version: string;
  ml_score: number;
  models_agreed?: boolean;
  rf_prediction?: string;
  rf_confidence?: number;
  rf_score?: number;
  cnn_prediction?: string;
  cnn_confidence?: number;
  cnn_score?: number;
}

export interface ThreatIntelAnalysis {
  total_engines_flagged: number;
  total_engines_checked: number;
  threat_score: number;
  threat_intel_failed: boolean;
  never_seen_before: boolean;
  rate_limited_incomplete: boolean;
}

export interface ScanResponse {
  id: number;
  url: string;
  source: string;
  verdict: string;
  final_risk_score?: number;
  fusion_method?: string;
  final_weights?: Record<string, number>;
  engines_used?: string[];
  engines_failed?: string[];
  engines_incomplete?: string[];
  lexical_analysis: LexicalAnalysis | null;
  domain_analysis: DomainAnalysis | null;
  behavior_analysis: BehaviorAnalysis | null;
  ml_analysis: MLAnalysis | null;
  threat_intelligence_analysis: ThreatIntelAnalysis | null;
}

const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export async function submitScan(
  url: string,
  source: "email" | "social_media" | "message"
): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, source }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    const detail = errorBody?.detail;
    let message = "";
    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail) && detail[0]?.msg) {
      message = detail[0].msg;
    } else if (response.status === 503) {
      message = "Scanner busy, try again";
    } else if (response.status === 429) {
      message = "Rate limit exceeded: maximum 10 scans per hour";
    } else {
      message = `Request failed with status ${response.status}`;
    }
    throw new Error(message);
  }

  return response.json();
}

export async function checkBackendHealth(): Promise<{ message: string }> {
  const response = await fetch(`${API_BASE}/`);
  if (!response.ok) {
    throw new Error(`Backend returned status ${response.status}`);
  }
  return response.json();
}
