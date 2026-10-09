import React, { useEffect, useState } from "react";
import {
  BarChart3,
  TrendingUp,
  Download,
  FileText,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  Globe,
  Hash,
  Database,
  Printer,
  CheckCircle2,
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  AreaChart,
  Area,
} from "recharts";
import { getStats } from "../services/api";
import type { Stats } from "../types/analysis";

export const AnalyticsPage: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getStats()
      .then((data) => {
        setStats(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to load analytics");
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-4 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
          <p className="text-sm font-mono text-slate-400">Aggregating telemetry analytics...</p>
        </div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="p-6 rounded-2xl bg-rose-950/20 border border-rose-800/40 text-rose-300">
          <h2 className="text-lg font-bold font-mono">Telemetry Unavailable</h2>
          <p className="text-sm mt-1">{error}</p>
        </div>
      </div>
    );
  }

  const safePct = stats.total > 0 ? ((stats.safe / stats.total) * 100).toFixed(1) : "0.0";
  const suspPct = stats.total > 0 ? ((stats.suspicious / stats.total) * 100).toFixed(1) : "0.0";
  const malPct = stats.total > 0 ? ((stats.malicious / stats.total) * 100).toFixed(1) : "0.0";
  const revPct = stats.total > 0 ? ((stats.manual_review / stats.total) * 100).toFixed(1) : "0.0";

  const handlePrint = () => {
    window.print();
  };

  const handleExportStatsJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(stats, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `etas-analytics-${new Date().toISOString().split("T")[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Title & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-slate-100">
            Threat Intelligence Reports & Executive Analytics
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Aggregate detection metrics, classification distribution, indicator frequency, and audit summaries.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportStatsJson}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono font-semibold text-slate-200"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            EXPORT TELEMETRY JSON
          </button>
          <button
            onClick={handlePrint}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300"
          >
            <Printer className="w-3.5 h-3.5" />
            PRINT REPORT
          </button>
        </div>
      </div>

      {/* Metric Breakdown Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-emerald-950/20 border border-emerald-900/40 space-y-2">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-xs font-mono font-semibold uppercase">SAFE PROPORTION</span>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-slate-100">{safePct}%</span>
            <span className="text-xs font-mono text-slate-400">({stats.safe} records)</span>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-amber-950/20 border border-amber-900/40 space-y-2">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-xs font-mono font-semibold uppercase">SUSPICIOUS PROPORTION</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-slate-100">{suspPct}%</span>
            <span className="text-xs font-mono text-slate-400">({stats.suspicious} records)</span>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-rose-950/20 border border-rose-900/40 space-y-2">
          <div className="flex items-center justify-between text-rose-400">
            <span className="text-xs font-mono font-semibold uppercase">MALICIOUS PROPORTION</span>
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-slate-100">{malPct}%</span>
            <span className="text-xs font-mono text-slate-400">({stats.malicious} records)</span>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-purple-950/20 border border-purple-900/40 space-y-2">
          <div className="flex items-center justify-between text-purple-400">
            <span className="text-xs font-mono font-semibold uppercase">MANUAL REVIEW</span>
            <HelpCircle className="w-4 h-4" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-slate-100">{revPct}%</span>
            <span className="text-xs font-mono text-slate-400">({stats.manual_review} records)</span>
          </div>
        </div>
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Detection Rule Trigger Volume */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
              Rule Trigger Distribution
            </h3>
            <span className="text-xs font-mono text-cyan-400">Hit Frequency</span>
          </div>
          <div className="h-64">
            {stats.top_rules && stats.top_rules.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.top_rules} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                  <YAxis
                    dataKey="rule_id"
                    type="category"
                    stroke="#64748b"
                    fontSize={11}
                    fontFamily="monospace"
                    width={80}
                  />
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#1e293b",
                      borderRadius: "8px",
                      fontFamily: "monospace",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} name="Trigger Count" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
                No detection rules have triggered yet.
              </div>
            )}
          </div>
        </div>

        {/* 14-Day Average Risk Score Trend */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
              14-Day Temporal Risk Trajectory
            </h3>
            <span className="text-xs font-mono text-cyan-400">Score Gradient (0-100)</span>
          </div>
          <div className="h-64">
            {stats.risk_trend && stats.risk_trend.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.risk_trend}>
                  <defs>
                    <linearGradient id="analyticsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                  <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} fontFamily="monospace" />
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#1e293b",
                      borderRadius: "8px",
                      fontFamily: "monospace",
                      fontSize: "12px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="avg_score"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#analyticsGrad)"
                    name="Average Score"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
                Temporal trend points will populate as records accumulate.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* System Methodology & Academic Specifications Box */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4 font-mono text-xs">
        <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase">
          Engine Architecture & Academic Compliance
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-slate-300">
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1.5">
            <span className="font-bold text-cyan-400">1. INPUT PARSING</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              RFC 5322 compliant message parsing, MIME multipart tree recursion, safe plain-text stripping, and lexical URL extraction without network sockets.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1.5">
            <span className="font-bold text-cyan-400">2. STATIC ARTIFACT INSPECTION</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              SHA-256 cryptographic digests, binary magic byte vs MIME classification, zipfile traversal defenses, and dangerous extension mapping.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1.5">
            <span className="font-bold text-cyan-400">3. CORRELATION & SAFEGUARDS</span>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Explainable 0–100 risk scoring, single-anomaly dampening safeguard, independent category correlation, and manual review routing.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
