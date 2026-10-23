/**
 * EngineCard — reusable card for displaying analysis engine results.
 *
 * Takes a title, a 0-100 score, and a list of {label, value} items.
 * Left border color adapts to the score range (green/amber/red).
 *
 * States:
 * - normal: score + items displayed
 * - failed: muted, "analysis failed" message
 * - neverSeen: neutral info styling, "URL never seen" message (NOT green all-clear)
 * - incomplete: muted amber, "rate-limited / incomplete" message
 */

import type { ReactNode } from "react";

interface EngineItem {
  label: string;
  value: ReactNode;
}

interface EngineCardProps {
  title: string;
  score: number;
  items: EngineItem[];
  failed?: boolean;
  neverSeen?: boolean;
  incomplete?: boolean;
  failureReason?: string | null;
}

function getBorderColor(score: number, failed?: boolean, neverSeen?: boolean, incomplete?: boolean): string {
  if (failed) return "border-l-slate-600";
  if (neverSeen) return "border-l-sky-500";
  if (incomplete) return "border-l-amber-600";
  if (score <= 30) return "border-l-emerald-500";
  if (score <= 60) return "border-l-amber-500";
  return "border-l-red-500";
}

function getBarColor(score: number, failed?: boolean, neverSeen?: boolean, incomplete?: boolean): string {
  if (failed) return "bg-slate-600";
  if (neverSeen) return "bg-sky-500";
  if (incomplete) return "bg-amber-600";
  if (score <= 30) return "bg-emerald-500";
  if (score <= 60) return "bg-amber-500";
  return "bg-red-500";
}

function getBarGlow(score: number, failed?: boolean, neverSeen?: boolean, incomplete?: boolean): string {
  if (failed || neverSeen || incomplete) return "";
  if (score <= 30) return "shadow-emerald-500/30";
  if (score <= 60) return "shadow-amber-500/30";
  return "shadow-red-500/30";
}

export function Badge({ positive }: { positive: boolean }) {
  return positive ? (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
      Yes
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
      </svg>
      No
    </span>
  );
}

export default function EngineCard({ title, score, items, failed, neverSeen, incomplete, failureReason }: EngineCardProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));

  return (
    <div
      className={`bg-slate-900/70 border border-slate-800 border-l-[3px] ${getBorderColor(clamped, failed, neverSeen, incomplete)} rounded-lg p-5 ${failed ? 'opacity-70' : ''}`}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-200 tracking-wide">
          {title}
        </h3>
        <span className="text-xs font-mono text-slate-500">
          {failed ? "N/A" : neverSeen ? "—" : incomplete ? "…" : `${clamped}/100`}
        </span>
      </div>

      {/* Score bar */}
      <div className="h-1.5 w-full bg-slate-800/80 rounded-full mb-5 overflow-hidden">
        {neverSeen ? (
          <div
            className="h-full w-full rounded-full opacity-60"
            style={{
              backgroundImage: "repeating-linear-gradient(-45deg, transparent, transparent 5px, rgba(56, 189, 248, 0.45) 5px, rgba(56, 189, 248, 0.45) 10px)"
            }}
          />
        ) : incomplete ? (
          <div
            className="h-full w-full rounded-full opacity-60"
            style={{
              backgroundImage: "repeating-linear-gradient(-45deg, transparent, transparent 5px, rgba(217, 119, 6, 0.5) 5px, rgba(217, 119, 6, 0.5) 10px)"
            }}
          />
        ) : (
          <div
            className={`h-full rounded-full ${getBarColor(clamped, failed, neverSeen, incomplete)} shadow-sm ${getBarGlow(clamped, failed, neverSeen, incomplete)} transition-all duration-500`}
            style={{ width: failed ? "100%" : `${clamped}%` }}
          />
        )}
      </div>

      {/* Items grid */}
      <div className="space-y-2.5">
        {failed ? (
          <div className="flex items-center gap-2 text-xs text-slate-400 italic">
            <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span>
              {failureReason === "dns_failure"
                ? "Analysis failed — domain unreachable"
                : failureReason === "timeout"
                ? "Analysis failed — request timed out"
                : failureReason === "blocked"
                ? "Analysis failed — site blocked automated access"
                : failureReason === "blocked_private_address"
                ? "Analysis blocked — target resolves to a private/internal address"
                : "Analysis failed — site blocked automated access or timed out"}
            </span>
          </div>
        ) : neverSeen ? (
          <div className="flex items-center gap-2 text-xs text-sky-400/80 italic">
            <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>No prior reports — URL never seen by VirusTotal</span>
          </div>
        ) : incomplete ? (
          <div className="flex items-center gap-2 text-xs text-amber-500/80 italic">
            <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>Rate-limited — analysis incomplete, excluded from score</span>
          </div>
        ) : (
          items.map((item) => (
            <div key={item.label} className="flex items-center justify-between">
              <span className="text-xs text-slate-500">{item.label}</span>
              <span className="text-xs text-slate-300 font-medium text-right max-w-[55%] truncate">
                {item.value}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
