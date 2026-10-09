import React, { useEffect, useState } from "react";
import {
  Sliders,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  Shield,
  Layers,
  Search,
} from "lucide-react";
import { getRules, toggleRule } from "../services/api";
import type { DetectionRule } from "../types/analysis";

export const RulesPage: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchRulesList = () => {
    setLoading(true);
    getRules()
      .then((data) => {
        setRules(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to load rules");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchRulesList();
  }, []);

  const handleToggle = async (ruleId: string, currentEnabled: boolean) => {
    setTogglingId(ruleId);
    const nextState = !currentEnabled;

    // Optimistic update
    setRules((prev) =>
      prev.map((r) => (r.rule_id === ruleId ? { ...r, enabled: nextState } : r))
    );

    try {
      await toggleRule(ruleId, nextState);
      setSuccessMsg(`Rule ${ruleId} successfully ${nextState ? "enabled" : "disabled"}`);
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      // Rollback on failure
      setRules((prev) =>
        prev.map((r) => (r.rule_id === ruleId ? { ...r, enabled: currentEnabled } : r))
      );
      alert("Failed to toggle rule: " + (err.message || "Unknown error"));
    } finally {
      setTogglingId(null);
    }
  };

  const categories = ["all", "email", "url", "attachment", "correlation", "parser", "intel"];

  const filteredRules = rules.filter((r) => {
    const matchesCategory =
      selectedCategory === "all" || r.category.toLowerCase() === selectedCategory;
    const matchesSearch =
      r.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.description.toLowerCase().includes(search.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-slate-100">
            Detection Rules Engine & Policies
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Configure active heuristics, view detection logic summaries, and track real-world rule trigger counts.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg self-start sm:self-auto">
          RULES LOADED: <strong className="text-cyan-400">{rules.length}</strong>
        </div>
      </div>

      {/* Audit Banner */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3 text-xs font-mono text-slate-400">
        <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div>
          <strong className="text-slate-300">RULE CONFIGURATION & AUDITING:</strong> Rules can be dynamically enabled or disabled per organizational security policy. All rule state toggles generate persistent audit log entries with administrative traceability.
        </div>
      </div>

      {/* Success Notification */}
      {successMsg && (
        <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs font-mono flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col md:flex-row gap-4 justify-between items-center">
        {/* Category Pills */}
        <div className="flex flex-wrap gap-1.5 w-full md:w-auto">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase tracking-wider transition-all ${
                selectedCategory === cat
                  ? "bg-cyan-600 text-white font-bold"
                  : "bg-slate-950/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800"
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules..."
            className="w-full rounded-xl bg-slate-950/80 border border-slate-800 pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/80"
          />
        </div>
      </div>

      {/* Rules Grid */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center gap-2">
          <div className="w-8 h-8 border-3 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
          <p className="text-xs font-mono text-slate-400">Loading detection catalog...</p>
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="py-16 text-center text-xs font-mono text-slate-500 p-8 rounded-2xl bg-slate-900/40 border border-slate-800">
          No detection rules match the selected filter.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredRules.map((rule) => {
            const isToggling = togglingId === rule.rule_id;
            return (
              <div
                key={rule.rule_id}
                className={`p-5 rounded-2xl border transition-all ${
                  rule.enabled
                    ? "bg-slate-900/70 border-slate-800 hover:border-slate-700"
                    : "bg-slate-950/40 border-slate-900 opacity-60"
                } flex flex-col justify-between space-y-4`}
              >
                {/* Header */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-mono text-xs font-bold">
                        {rule.rule_id}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 uppercase">
                        {rule.category}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                          rule.severity === "high"
                            ? "bg-rose-950/80 text-rose-300 border border-rose-800/60"
                            : rule.severity === "medium"
                            ? "bg-amber-950/80 text-amber-300 border border-amber-800/60"
                            : "bg-emerald-950/80 text-emerald-300 border border-emerald-800/60"
                        }`}
                      >
                        {rule.severity}
                      </span>
                    </div>

                    {/* Toggle Switch */}
                    <button
                      type="button"
                      disabled={isToggling}
                      onClick={() => handleToggle(rule.rule_id, rule.enabled)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
                        rule.enabled ? "bg-cyan-600" : "bg-slate-800"
                      }`}
                      title={rule.enabled ? "Click to disable rule" : "Click to enable rule"}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          rule.enabled ? "translate-x-6" : "translate-x-1"
                        }`}
                      />
                    </button>
                  </div>

                  <h3 className="text-sm font-bold font-mono text-slate-100">{rule.name}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{rule.description}</p>
                </div>

                {/* Logic Summary Box */}
                <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 text-xs font-mono space-y-1">
                  <span className="text-[11px] font-bold text-slate-400">DETECTION LOGIC:</span>
                  <p className="text-slate-300">{rule.logic_summary}</p>
                </div>

                {/* Footer Metrics */}
                <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs font-mono text-slate-400">
                  <span>
                    Default Score Contribution:{" "}
                    <strong className="text-amber-300 font-bold">+{rule.default_score} pts</strong>
                  </span>
                  <span className="flex items-center gap-1.5">
                    Triggered in Database:{" "}
                    <strong className="text-slate-200 px-1.5 py-0.5 rounded bg-slate-800 font-bold">
                      {rule.times_triggered}
                    </strong>
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
