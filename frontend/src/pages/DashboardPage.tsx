import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  TrendingUp,
  Inbox,
  FileSearch,
  ExternalLink,
  Copy,
  Check,
  Globe,
  Hash,
  AlertOctagon,
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip as RechartsTooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  BarChart,
  Bar,
} from "recharts";
import { getStats } from "../services/api";
import type { Stats } from "../types/analysis";
import { ClassificationBadge } from "../components/ClassificationBadge";

export const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    getStats()
      .then((data) => {
        setStats(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to load dashboard statistics");
        setLoading(false);
      });
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-4 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
          <p className="text-sm font-mono text-slate-400">Loading security telemetry...</p>
        </div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="p-6 rounded-2xl bg-rose-950/20 border border-rose-800/40 text-rose-300">
          <h2 className="text-lg font-bold">Failed to load statistics</h2>
          <p className="text-sm mt-1">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 px-4 py-2 rounded-lg bg-rose-900/60 hover:bg-rose-800/60 text-xs font-mono"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Distribution chart data
  const distributionData = [
    { name: "Safe", value: stats.safe, color: "#10b981" },
    { name: "Suspicious", value: stats.suspicious, color: "#f59e0b" },
    { name: "Malicious", value: stats.malicious, color: "#ef4444" },
    { name: "Manual Review", value: stats.manual_review, color: "#8b5cf6" },
  ].filter((d) => d.value > 0);

  const kpis = [
    {
      title: "Total Analyzed",
      value: stats.total,
      icon: Inbox,
      color: "text-cyan-400",
      bg: "bg-cyan-950/20 border-cyan-900/40",
    },
    {
      title: "Safe Emails",
      value: stats.safe,
      icon: ShieldCheck,
      color: "text-emerald-400",
      bg: "bg-emerald-950/20 border-emerald-900/40",
    },
    {
      title: "Suspicious",
      value: stats.suspicious,
      icon: AlertTriangle,
      color: "text-amber-400",
      bg: "bg-amber-950/20 border-amber-900/40",
    },
    {
      title: "Malicious",
      value: stats.malicious,
      icon: ShieldAlert,
      color: "text-rose-400",
      bg: "bg-rose-950/20 border-rose-900/40",
    },
    {
      title: "Manual Review",
      value: stats.manual_review,
      icon: HelpCircle,
      color: "text-purple-400",
      bg: "bg-purple-950/20 border-purple-900/40",
    },
    {
      title: "High-Risk Cases (≥60)",
      value: stats.high_risk,
      icon: AlertOctagon,
      color: "text-red-500",
      bg: "bg-red-950/30 border-red-900/50",
    },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 border border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
            Security Operations Center Overview
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Static heuristics, sender spoofing detection, URL inspection, and attachment hashing.
          </p>
        </div>
        <Link
          to="/analyze"
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold tracking-wider transition-colors shadow-lg shadow-cyan-900/20"
        >
          <FileSearch className="w-4 h-4" />
          START NEW ANALYSIS
        </Link>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        {kpis.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <div
              key={kpi.title}
              className={`p-4 rounded-xl border backdrop-blur-sm ${kpi.bg} flex flex-col justify-between`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  {kpi.title}
                </span>
                <Icon className={`w-4 h-4 ${kpi.color}`} />
              </div>
              <div className="mt-3">
                <span className="text-3xl font-extrabold font-mono text-slate-100">
                  {kpi.value}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {stats.total === 0 ? (
        /* Empty State */
        <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800/80">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-slate-800/60 border border-slate-700/60 flex items-center justify-center text-slate-400 mb-4">
            <Inbox className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-bold text-slate-200 font-mono">No Email Telemetry Recorded</h3>
          <p className="text-sm text-slate-400 max-w-md mx-auto mt-2">
            No emails or security artifacts have been analyzed yet. Upload an .eml message or inspect a suspicious URL to populate live telemetry.
          </p>
          <div className="mt-6 flex justify-center gap-3">
            <Link
              to="/analyze"
              className="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold"
            >
              Analyze First Email
            </Link>
          </div>
        </div>
      ) : (
        <>
          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Threat Distribution Chart */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                  Threat Classification Breakdown
                </h3>
                <span className="text-xs font-mono text-slate-400">{stats.total} total</span>
              </div>
              <div className="h-64">
                {distributionData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={distributionData}
                        innerRadius={65}
                        outerRadius={95}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {distributionData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{
                          backgroundColor: "#0f172a",
                          borderColor: "#1e293b",
                          borderRadius: "8px",
                          fontFamily: "monospace",
                          fontSize: "12px",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    No data
                  </div>
                )}
              </div>
              <div className="flex flex-wrap justify-center gap-4 mt-2">
                {distributionData.map((d) => (
                  <div key={d.name} className="flex items-center gap-1.5 text-xs font-mono">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                    <span className="text-slate-300">{d.name}:</span>
                    <span className="text-slate-100 font-bold">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Risk Trend Chart */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                  Risk Trend (Last 14 Days)
                </h3>
                <span className="text-xs font-mono text-cyan-400 flex items-center gap-1">
                  <TrendingUp className="w-3.5 h-3.5" /> Average Risk
                </span>
              </div>
              <div className="h-64">
                {stats.risk_trend && stats.risk_trend.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={stats.risk_trend}>
                      <defs>
                        <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
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
                        stroke="#06b6d4"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#scoreGrad)"
                        name="Avg Risk Score"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
                    Trend data will appear as analyses are recorded over time.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Rules & IoCs Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Top Triggered Detection Rules */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 lg:col-span-1">
              <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase mb-4">
                Most Frequent Detection Rules
              </h3>
              {stats.top_rules && stats.top_rules.length > 0 ? (
                <div className="space-y-3">
                  {stats.top_rules.slice(0, 6).map((rule) => (
                    <div
                      key={rule.rule_id}
                      className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center justify-between"
                    >
                      <div className="space-y-0.5">
                        <span className="text-xs font-mono font-bold text-cyan-400">
                          {rule.rule_id}
                        </span>
                        <p className="text-[11px] text-slate-300 truncate max-w-[180px]">
                          {rule.rule_name}
                        </p>
                      </div>
                      <span className="px-2 py-0.5 rounded-full bg-slate-800 text-xs font-mono font-bold text-slate-200">
                        {rule.count} hits
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 font-mono py-8 text-center">
                  No detection rules triggered yet.
                </p>
              )}
            </div>

            {/* Suspicious Domains & Hashes */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 lg:col-span-2 space-y-6">
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                    Observed Sender & Extracted Domains
                  </h3>
                </div>
                {stats.recent_domains && stats.recent_domains.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {stats.recent_domains.map((dom) => (
                      <span
                        key={dom.domain}
                        className="px-2.5 py-1 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5"
                      >
                        <span>{dom.domain}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-bold">
                          {dom.count}
                        </span>
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No domains recorded.</p>
                )}
              </div>

              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Hash className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                    Recent Attachment SHA-256 Hashes
                  </h3>
                </div>
                {stats.recent_hashes && stats.recent_hashes.length > 0 ? (
                  <div className="space-y-2">
                    {stats.recent_hashes.slice(0, 4).map((hashVal) => (
                      <div
                        key={hashVal}
                        className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 flex items-center justify-between gap-3 text-xs font-mono"
                      >
                        <span className="text-slate-400 truncate max-w-md">{hashVal}</span>
                        <button
                          onClick={() => handleCopy(hashVal)}
                          className="text-slate-400 hover:text-cyan-400 transition-colors p-1"
                          title="Copy SHA-256"
                        >
                          {copiedHash === hashVal ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No artifact hashes recorded.</p>
                )}
              </div>
            </div>
          </div>

          {/* Recent Analyses Table */}
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                Recent Security Assessments
              </h3>
              <Link
                to="/history"
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                View Complete History <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">CASE ID</th>
                    <th className="py-2.5 px-3">TYPE</th>
                    <th className="py-2.5 px-3">SUBJECT / TARGET</th>
                    <th className="py-2.5 px-3">CLASSIFICATION</th>
                    <th className="py-2.5 px-3">RISK SCORE</th>
                    <th className="py-2.5 px-3 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {stats.recent && stats.recent.length > 0 ? (
                    stats.recent.map((item) => (
                      <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3 px-3 font-semibold text-slate-200">
                          {item.id.slice(0, 8)}...
                        </td>
                        <td className="py-3 px-3 text-slate-400 uppercase">
                          {item.analysis_type.replace("_", " ")}
                        </td>
                        <td className="py-3 px-3 max-w-xs truncate text-slate-200">
                          {item.subject || item.original_filename || "N/A"}
                        </td>
                        <td className="py-3 px-3">
                          <ClassificationBadge classification={item.classification} size="sm" />
                        </td>
                        <td className="py-3 px-3 font-bold">
                          <span
                            className={
                              item.risk_score >= 60
                                ? "text-rose-400"
                                : item.risk_score >= 30
                                ? "text-amber-400"
                                : "text-emerald-400"
                            }
                          >
                            {item.risk_score} / 100
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right">
                          <Link
                            to={`/analysis/${item.id}`}
                            className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-semibold"
                          >
                            Details <ExternalLink className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        No recent analyses recorded.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
