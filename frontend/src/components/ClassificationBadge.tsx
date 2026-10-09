import React from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle } from "lucide-react";
import type { Classification } from "../types/analysis";

interface Props {
  classification: Classification;
  className?: string;
  size?: "sm" | "md" | "lg";
}

export const ClassificationBadge: React.FC<Props> = ({
  classification,
  className = "",
  size = "md",
}) => {
  const config = {
    safe: {
      label: "Safe",
      bg: "bg-emerald-950/60 border-emerald-500/40 text-emerald-400",
      icon: ShieldCheck,
    },
    suspicious: {
      label: "Suspicious",
      bg: "bg-amber-950/60 border-amber-500/40 text-amber-400",
      icon: AlertTriangle,
    },
    malicious: {
      label: "Malicious",
      bg: "bg-rose-950/60 border-rose-500/40 text-rose-400",
      icon: ShieldAlert,
    },
    manual_review: {
      label: "Manual Review",
      bg: "bg-purple-950/60 border-purple-500/40 text-purple-400",
      icon: HelpCircle,
    },
  }[classification] || {
    label: classification,
    bg: "bg-slate-800 border-slate-700 text-slate-300",
    icon: HelpCircle,
  };

  const Icon = config.icon;

  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs gap-1",
    md: "px-2.5 py-1 text-xs font-semibold gap-1.5",
    lg: "px-3.5 py-1.5 text-sm font-semibold gap-2",
  }[size];

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-full border shadow-sm font-mono tracking-wide uppercase ${config.bg} ${sizeClasses} ${className}`}
    >
      <Icon size={iconSizes} />
      <span>{config.label}</span>
    </span>
  );
};
