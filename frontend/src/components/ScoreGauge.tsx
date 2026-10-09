import React from "react";

interface Props {
  score: number;
  size?: number;
  strokeWidth?: number;
}

export const ScoreGauge: React.FC<Props> = ({ score, size = 160, strokeWidth = 12 }) => {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  let color = "#10b981"; // emerald
  let glowColor = "rgba(16, 185, 129, 0.3)";
  let label = "LOW RISK";

  if (clampedScore >= 60) {
    color = "#ef4444"; // rose
    glowColor = "rgba(239, 68, 68, 0.4)";
    label = "HIGH RISK";
  } else if (clampedScore >= 30) {
    color = "#f59e0b"; // amber
    glowColor = "rgba(245, 158, 11, 0.35)";
    label = "MEDIUM RISK";
  }

  return (
    <div className="flex flex-col items-center justify-center relative">
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        {/* Animated Progress */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          style={{
            filter: `drop-shadow(0 0 8px ${glowColor})`,
            transition: "stroke-dashoffset 0.8s ease-in-out, stroke 0.3s ease",
          }}
        />
      </svg>
      {/* Center Score */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-4xl font-extrabold font-mono tracking-tight text-slate-100">
          {clampedScore}
        </span>
        <span className="text-[10px] font-mono tracking-wider font-semibold text-slate-400 mt-0.5">
          / 100
        </span>
        <span
          className="text-[10px] font-bold font-mono tracking-widest mt-1 uppercase"
          style={{ color }}
        >
          {label}
        </span>
      </div>
    </div>
  );
};
