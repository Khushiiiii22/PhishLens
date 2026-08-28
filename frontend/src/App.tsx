import { useState, useEffect, useRef, useCallback } from "react";
import { submitScan, type ScanResponse } from "./api/scan";
import ResultsDashboard from "./components/ResultsDashboard";

type Source = "email" | "social_media" | "message";

const SOURCE_OPTIONS: { value: Source; label: string }[] = [
  { value: "email", label: "Email" },
  { value: "social_media", label: "Social Media" },
  { value: "message", label: "Message" },
];

const ANALYSIS_STEPS = [
  "Extracting URL features…",
  "Computing Shannon entropy…",
  "Looking up WHOIS records…",
  "Checking domain age…",
  "Verifying SSL certificate…",
  "Querying DNS records…",
  "Calculating risk scores…",
];

function isValidUrl(input: string): boolean {
  return /^https?:\/\/.+\..+/.test(input.trim());
}

function Spinner() {
  return (
    <svg
      className="animate-spin h-4 w-4"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle
        className="opacity-25"
        cx="12" cy="12" r="10"
        stroke="currentColor" strokeWidth="3"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

function App() {
  const [url, setUrl] = useState("");
  const [source, setSource] = useState<Source | null>(null);
  const [scanning, setScanning] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const canSubmit = isValidUrl(url) && source !== null && !scanning;

  // Rotate through analysis step messages while scanning
  useEffect(() => {
    if (scanning) {
      setStepIndex(0);
      intervalRef.current = setInterval(() => {
        setStepIndex((prev) =>
          prev < ANALYSIS_STEPS.length - 1 ? prev + 1 : prev
        );
      }, 1800);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [scanning]);

  const handleSubmit = useCallback(async () => {
    if (!canSubmit || !source) return;

    setScanning(true);
    setError(null);

    try {
      const result: ScanResponse = await submitScan(url.trim(), source);
      setScanResult(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "An unexpected error occurred";
      setError(msg);
    } finally {
      setScanning(false);
    }
  }, [url, source, canSubmit]);

  const handleReset = useCallback(() => {
    setScanResult(null);
    setUrl("");
    setSource(null);
    setError(null);
  }, []);

  // ─── RESULTS VIEW ───
  if (scanResult) {
    return <ResultsDashboard result={scanResult} onReset={handleReset} />;
  }

  // ─── SUBMISSION FORM ───
  return (
    <div className="min-h-screen bg-[#0F172A] flex flex-col items-center justify-center px-4 py-12 font-sans antialiased">

      {/* Wordmark */}
      <div className="mb-10 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-white">
          Phish<span className="text-[#22D3EE]">Lens</span> XAI
        </h1>
        <p className="mt-1.5 text-sm text-slate-500 tracking-wide">
          Multi-engine phishing detection
        </p>
      </div>

      {/* Card */}
      <div className="w-full max-w-[600px] bg-slate-900/70 border border-slate-800 rounded-lg p-8">

        {/* URL Input */}
        <label htmlFor="url-input" className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
          Target URL
        </label>
        <input
          id="url-input"
          type="text"
          value={url}
          onChange={(e) => { setUrl(e.target.value); setError(null); }}
          placeholder="Paste a suspicious link…"
          disabled={scanning}
          autoComplete="off"
          spellCheck={false}
          className="w-full bg-slate-950 border border-slate-700 rounded-md px-4 py-3 text-sm text-slate-200 placeholder-slate-600 outline-none transition-colors focus:border-[#22D3EE] focus:ring-1 focus:ring-[#22D3EE]/30 disabled:opacity-50"
        />
        {url.length > 0 && !isValidUrl(url) && (
          <p className="mt-1.5 text-xs text-red-400">
            Enter a valid URL starting with http:// or https://
          </p>
        )}

        {/* Source Selector */}
        <p className="mt-6 text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
          Source
        </p>
        <div className="flex gap-2">
          {SOURCE_OPTIONS.map((opt) => {
            const active = source === opt.value;
            return (
              <button
                key={opt.value}
                id={`source-${opt.value}`}
                type="button"
                onClick={() => { setSource(opt.value); setError(null); }}
                disabled={scanning}
                className={`
                  flex-1 py-2 px-3 rounded-md text-sm font-medium transition-all
                  ${active
                    ? "bg-[#22D3EE]/10 border border-[#22D3EE] text-[#22D3EE]"
                    : "bg-slate-800 border border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-300"
                  }
                  disabled:opacity-50 disabled:cursor-not-allowed
                `}
              >
                {opt.label}
              </button>
            );
          })}
        </div>

        {/* Submit Button */}
        <button
          id="scan-button"
          type="button"
          onClick={handleSubmit}
          disabled={!canSubmit}
          className={`
            mt-8 w-full py-3 rounded-md text-sm font-semibold tracking-wide
            flex items-center justify-center gap-2 transition-all
            ${canSubmit
              ? "bg-[#22D3EE] text-slate-950 hover:bg-[#22D3EE]/90 active:scale-[0.98]"
              : "bg-slate-800 text-slate-600 cursor-not-allowed"
            }
          `}
        >
          {scanning ? (
            <>
              <Spinner />
              Analyzing…
            </>
          ) : (
            "Scan URL"
          )}
        </button>

        {/* Analysis progress indicator */}
        {scanning && (
          <div className="mt-4 flex items-center gap-2.5">
            <div className="h-1 w-1 rounded-full bg-[#22D3EE] animate-pulse" />
            <p className="text-xs text-slate-500 transition-all duration-300">
              {ANALYSIS_STEPS[stepIndex]}
            </p>
          </div>
        )}

        {/* Error display */}
        {error && (
          <div className="mt-4 bg-red-950/30 border border-red-900/40 rounded-md px-4 py-3">
            <p className="text-xs text-red-400">{error}</p>
          </div>
        )}
      </div>

      <p className="mt-6 text-[11px] text-slate-700">
        Results are for informational purposes only.
      </p>
    </div>
  );
}

export default App;
