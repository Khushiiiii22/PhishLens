/**
 * ResultsDashboard — displays the full scan results after a successful analysis.
 */

import type { ScanResponse } from "../api/scan";
import RiskGauge from "./RiskGauge";
import EngineCard, { Badge } from "./EngineCard";

interface ResultsDashboardProps {
  result: ScanResponse;
  onReset: () => void;
}

// Source icons (small inline SVGs)
const SOURCE_ICONS: Record<string, JSX.Element> = {
  email: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
  ),
  social_media: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
  message: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
    </svg>
  ),
};

const SOURCE_LABELS: Record<string, string> = {
  email: "Email",
  social_media: "Social Media",
  message: "Message",
};

function formatAge(days: number | null): string {
  if (days === null) return "Unknown";
  if (days >= 365) {
    const years = Math.floor(days / 365);
    return `${years} year${years !== 1 ? "s" : ""} (${days.toLocaleString()} days)`;
  }
  return `${days} day${days !== 1 ? "s" : ""}`;
}

export default function ResultsDashboard({ result, onReset }: ResultsDashboardProps) {
  const lexical = result.lexical_analysis;
  const domain = result.domain_analysis;
  const behavior = result.behavior_analysis;

  // TEMPORARY: combined score = average of all available engine scores.
  // TODO: Replace this with the real Adaptive Risk Fusion Engine score
  // once it is built. This is only a placeholder for display purposes.
  const lexScore = lexical?.lexical_score ?? 0;
  const domScore = domain?.domain_score ?? 0;
  const behScore = behavior?.behavior_score ?? 0;

  // Only count engines that actually produced a score
  let engineCount = 0;
  let totalScore = 0;
  if (lexical) { totalScore += lexScore; engineCount++; }
  if (domain) { totalScore += domScore; engineCount++; }
  if (behavior && !behavior.behavior_analysis_failed) { totalScore += behScore; engineCount++; }

  const combinedScore = engineCount > 0 ? Math.round(totalScore / engineCount) : 0;

  return (
    <div className="min-h-screen bg-[#0F172A] px-4 py-10 font-sans antialiased">
      <div className="max-w-[1080px] mx-auto">

        {/* Wordmark */}
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Phish<span className="text-[#22D3EE]">Lens</span>
          </h1>
        </div>

        {/* ─── 1. VERDICT HEADER ─── */}
        <div className="flex flex-col items-center mb-8">
          <RiskGauge score={combinedScore} />
        </div>

        {/* ─── 2. SCAN META ROW ─── */}
        <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 mb-8 text-xs text-slate-500">
          {/* URL */}
          <span
            className="max-w-[280px] truncate hover:max-w-none hover:whitespace-normal transition-all cursor-default"
            title={result.url}
          >
            {result.url}
          </span>

          <span className="text-slate-700">·</span>

          {/* Source badge */}
          <span className="inline-flex items-center gap-1.5 bg-slate-800 border border-slate-700 rounded-md px-2.5 py-1 text-slate-400">
            {SOURCE_ICONS[result.source]}
            {SOURCE_LABELS[result.source] ?? result.source}
          </span>

          <span className="text-slate-700">·</span>

          {/* Timestamp */}
          <span>
            {new Date().toLocaleString()}
          </span>
        </div>

        {/* ─── 3. ENGINE CARDS ─── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">

          {/* Lexical Analysis */}
          {lexical && (
            <EngineCard
              title="Lexical Analysis"
              score={lexical.lexical_score}
              items={[
                { label: "URL Length", value: `${lexical.url_length} chars` },
                { label: "Dot Count", value: String(lexical.dot_count) },
                { label: "Hyphen Count", value: String(lexical.hyphen_count) },
                { label: "Digit Count", value: String(lexical.digit_count) },
                { label: "Special Chars", value: String(lexical.special_char_count) },
                { label: "Entropy", value: lexical.entropy_score.toFixed(3) },
                {
                  label: "Suspicious Keywords",
                  value: <Badge positive={!lexical.has_suspicious_keywords} />,
                },
              ]}
            />
          )}

          {/* Domain Intelligence */}
          {domain && (
            <EngineCard
              title="Domain Intelligence"
              score={domain.domain_score}
              items={[
                { label: "Domain Age", value: formatAge(domain.domain_age_days) },
                { label: "Registrar", value: domain.registrar ?? "Unknown" },
                {
                  label: "SSL Valid",
                  value: <Badge positive={domain.ssl_valid} />,
                },
                { label: "SSL Issuer", value: domain.ssl_issuer ?? "—" },
                {
                  label: "DNSSEC",
                  value: <Badge positive={domain.dnssec_enabled} />,
                },
              ]}
            />
          )}

          {/* Website Behavior */}
          {behavior && (
            <EngineCard
              title="Website Behavior"
              score={behavior.behavior_score}
              items={
                behavior.behavior_analysis_failed
                  ? [
                      {
                        label: "Status",
                        value: (
                          <span className="text-xs text-slate-600 italic">
                            Page could not be analyzed (blocked or unreachable)
                          </span>
                        ),
                      },
                    ]
                  : [
                      {
                        label: "Login Form",
                        value: behavior.has_login_form
                          ? <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                              Login form detected
                            </span>
                          : <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                              No login form
                            </span>,
                      },
                      {
                        label: "Form Action",
                        value: behavior.external_form_action
                          ? <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                              External form action
                            </span>
                          : <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                              Form action is safe
                            </span>,
                      },
                      {
                        label: "Hidden Iframe",
                        value: behavior.has_hidden_iframe
                          ? <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                              Hidden iframe found
                            </span>
                          : <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                              No hidden iframes
                            </span>,
                      },
                      {
                        label: "JS Redirect",
                        value: behavior.has_js_redirect
                          ? <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                              Redirect detected
                            </span>
                          : <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                              No redirect
                            </span>,
                      },
                      {
                        label: "Popup",
                        value: behavior.popup_detected
                          ? <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                              Popup detected
                            </span>
                          : <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                              No popups
                            </span>,
                      },
                    ]
              }
            />
          )}
        </div>

        {/* ─── 4. SCAN ANOTHER ─── */}
        <div className="text-center">
          <button
            id="scan-another-button"
            type="button"
            onClick={onReset}
            className="px-6 py-2.5 rounded-md text-sm font-medium text-slate-400 border border-slate-700 hover:border-slate-600 hover:text-slate-300 transition-colors"
          >
            ← Scan another URL
          </button>
        </div>

      </div>
    </div>
  );
}
