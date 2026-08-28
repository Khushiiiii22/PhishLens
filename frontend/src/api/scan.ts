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
}

export interface ScanResponse {
  id: number;
  url: string;
  source: string;
  verdict: string;
  lexical_analysis: LexicalAnalysis | null;
  domain_analysis: DomainAnalysis | null;
  behavior_analysis: BehaviorAnalysis | null;
}

const API_BASE = "http://127.0.0.1:8000";

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
    throw new Error(
      errorBody?.detail?.[0]?.msg ?? `Request failed with status ${response.status}`
    );
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
