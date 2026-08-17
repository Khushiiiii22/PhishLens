/**
 * RiskGauge — circular arc score gauge (0-100).
 *
 * Green (0-30) → Amber (31-60) → Red (61-100).
 * Renders an SVG arc with a numeric score in the center and a verdict badge below.
 */

interface RiskGaugeProps {
  score: number; // 0-100
}

function getScoreColor(score: number): string {
  if (score <= 30) return "#22C55E";  // green-500
  if (score <= 60) return "#F59E0B";  // amber-500
  return "#EF4444";                    // red-500
}

function getScoreBg(score: number): string {
  if (score <= 30) return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
  if (score <= 60) return "bg-amber-500/15 text-amber-400 border-amber-500/30";
  return "bg-red-500/15 text-red-400 border-red-500/30";
}

function getVerdict(score: number): string {
  if (score <= 30) return "LOW RISK";
  if (score <= 60) return "MEDIUM RISK";
  return "HIGH RISK";
}

export default function RiskGauge({ score }: RiskGaugeProps) {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const color = getScoreColor(clampedScore);
  const verdict = getVerdict(clampedScore);
  const badgeClass = getScoreBg(clampedScore);

  // Arc geometry: 240° sweep, starting at 150° (7 o'clock)
  const radius = 70;
  const cx = 90;
  const cy = 90;
  const startAngle = 150;
  const totalSweep = 240;
  const sweepAngle = (clampedScore / 100) * totalSweep;

  const toRad = (deg: number) => (deg * Math.PI) / 180;

  const bgStartX = cx + radius * Math.cos(toRad(startAngle));
  const bgStartY = cy + radius * Math.sin(toRad(startAngle));
  const bgEndX = cx + radius * Math.cos(toRad(startAngle + totalSweep));
  const bgEndY = cy + radius * Math.sin(toRad(startAngle + totalSweep));

  const arcEndX = cx + radius * Math.cos(toRad(startAngle + sweepAngle));
  const arcEndY = cy + radius * Math.sin(toRad(startAngle + sweepAngle));

  const bgLargeArc = totalSweep > 180 ? 1 : 0;
  const arcLargeArc = sweepAngle > 180 ? 1 : 0;

  const bgPath = `M ${bgStartX} ${bgStartY} A ${radius} ${radius} 0 ${bgLargeArc} 1 ${bgEndX} ${bgEndY}`;
  const arcPath =
    sweepAngle > 0
      ? `M ${bgStartX} ${bgStartY} A ${radius} ${radius} 0 ${arcLargeArc} 1 ${arcEndX} ${arcEndY}`
      : "";

  return (
    <div className="flex flex-col items-center gap-3">
      <svg width="180" height="160" viewBox="0 0 180 160">
        {/* Background track */}
        <path
          d={bgPath}
          fill="none"
          stroke="#1E293B"
          strokeWidth="10"
          strokeLinecap="round"
        />
        {/* Score arc */}
        {arcPath && (
          <path
            d={arcPath}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 6px ${color}40)`,
              transition: "all 0.6s ease-out",
            }}
          />
        )}
        {/* Score number */}
        <text
          x={cx}
          y={cy - 4}
          textAnchor="middle"
          dominantBaseline="central"
          fill="white"
          fontSize="36"
          fontWeight="700"
          fontFamily="Inter, system-ui, sans-serif"
        >
          {clampedScore}
        </text>
        <text
          x={cx}
          y={cy + 22}
          textAnchor="middle"
          fill="#64748B"
          fontSize="11"
          fontFamily="Inter, system-ui, sans-serif"
          letterSpacing="0.05em"
        >
          / 100
        </text>
      </svg>

      {/* Verdict badge */}
      <span
        className={`px-4 py-1.5 rounded-md text-xs font-semibold tracking-widest border ${badgeClass}`}
      >
        {verdict}
      </span>
    </div>
  );
}
