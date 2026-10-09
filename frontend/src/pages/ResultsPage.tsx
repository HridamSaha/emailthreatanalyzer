import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Download,
  FileDown,
  Copy,
  Check,
  Globe,
  FileText,
  Paperclip,
  CheckCircle2,
  XCircle,
  ExternalLink,
  ChevronRight,
  Info,
  Sliders,
  ArrowLeft,
  Terminal,
} from "lucide-react";
import {
  getAnalysis,
  getPdfReportUrl,
  getExportUrl,
} from "../services/api";
import type { AnalysisResult } from "../types/analysis";
import { ClassificationBadge } from "../components/ClassificationBadge";
import { ScoreGauge } from "../components/ScoreGauge";

export const ResultsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<
    "summary" | "headers" | "body" | "urls" | "attachments" | "findings" | "iocs"
  >("summary");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    getAnalysis(id)
      .then((data) => {
        setAnalysis(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to load analysis record");
        setLoading(false);
      });
  }, [id]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-4 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
          <p className="text-sm font-mono text-slate-400">Retrieving security dossier...</p>
        </div>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <div className="p-8 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <AlertTriangle className="w-10 h-10 text-amber-400 mx-auto" />
          <h2 className="text-lg font-bold font-mono text-slate-200">Analysis Record Not Found</h2>
          <p className="text-sm text-slate-400">{error || "Case file could not be retrieved."}</p>
          <Link
            to="/history"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200"
          >
            <ArrowLeft className="w-4 h-4" /> Return to History
          </Link>
        </div>
      </div>
    );
  }

  const header = (analysis.header_analysis as any) || {};
  const urls = (analysis.url_analysis as any[]) || [];
  const attachments = (analysis.attachment_analysis as any[]) || [];
  const findings = analysis.findings || [];
  const indicators = analysis.indicators || [];
  const warnings = analysis.parser_warnings || [];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Top Breadcrumb & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Link
            to="/history"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            title="Back to History"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">ANALYSIS CASE:</span>
              <span className="text-xs font-mono font-bold text-cyan-400">{analysis.id}</span>
            </div>
            <h1 className="text-lg font-bold font-mono text-slate-100 truncate max-w-xl">
              {header.subject || analysis.original_filename || `Target: ${analysis.analysis_type.toUpperCase()}`}
            </h1>
          </div>
        </div>

        {/* Download & Export Actions */}
        <div className="flex items-center gap-2">
          <a
            href={getPdfReportUrl(analysis.id)}
            target="_blank"
            rel="noreferrer"
            download={`analysis-${analysis.id}.pdf`}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono font-semibold text-slate-200 transition-colors shadow-sm"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            PDF REPORT
          </a>
          <a
            href={getExportUrl(analysis.id, "json")}
            download={`analysis-${analysis.id}.json`}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 transition-colors"
          >
            <FileDown className="w-3.5 h-3.5" />
            JSON
          </a>
          <a
            href={getExportUrl(analysis.id, "csv")}
            download={`analysis-${analysis.id}.csv`}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 transition-colors"
          >
            <FileDown className="w-3.5 h-3.5" />
            CSV
          </a>
        </div>
      </div>

      {/* Hero Threat Summary Card */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-blue-950/30 border border-slate-800">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">
          {/* Gauge */}
          <div className="flex justify-center md:border-r md:border-slate-800/80 md:pr-6">
            <ScoreGauge score={analysis.risk_score} size={150} />
          </div>

          {/* Assessment Overview */}
          <div className="md:col-span-3 space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <ClassificationBadge classification={analysis.classification} size="lg" />
              <span className="px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700/60 text-xs font-mono text-slate-300">
                SEVERITY: <strong className="uppercase text-slate-100">{analysis.severity}</strong>
              </span>
              <span className="px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700/60 text-xs font-mono text-slate-300">
                EVIDENCE STRENGTH:{" "}
                <strong className="uppercase text-slate-100">{analysis.evidence_strength}</strong>
              </span>
              {analysis.created_at && (
                <span className="text-xs font-mono text-slate-500">
                  {new Date(analysis.created_at).toUTCString()}
                </span>
              )}
            </div>

            <div>
              <h2 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                Assessment Verdict
              </h2>
              <p className="text-sm text-slate-300 mt-1 leading-relaxed">{analysis.summary}</p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3">
              <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs font-mono text-slate-300">
                <span className="font-bold text-cyan-300">RECOMMENDED ACTION:</span>{" "}
                {analysis.recommended_action}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Parser Warnings Notice */}
      {warnings.length > 0 && (
        <div className="p-4 rounded-xl bg-purple-950/30 border border-purple-800/50 text-xs font-mono space-y-1">
          <div className="flex items-center gap-2 font-bold text-purple-300">
            <HelpCircle className="w-4 h-4 text-purple-400" />
            <span>EXTRACTION NOTICES & PARSER WARNINGS ({warnings.length}):</span>
          </div>
          <ul className="list-disc list-inside text-purple-200/90 pl-1 space-y-0.5">
            {warnings.map((w, idx) => (
              <li key={idx}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex overflow-x-auto gap-2 border-b border-slate-800 pb-2 text-xs font-mono">
        {[
          { key: "summary", label: `Evidence Overview (${findings.length})` },
          { key: "headers", label: "Header Analysis" },
          { key: "body", label: "Email Body Content" },
          { key: "urls", label: `Extracted URLs (${urls.length})` },
          { key: "attachments", label: `Attachments (${attachments.length})` },
          { key: "findings", label: `Triggered Rules (${findings.length})` },
          { key: "iocs", label: `Indicators of Compromise (${indicators.length})` },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as any)}
            className={`px-4 py-2 rounded-xl whitespace-nowrap font-semibold transition-all ${
              activeTab === tab.key
                ? "bg-slate-800 text-cyan-300 border border-slate-700 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content Panels */}
      <div className="space-y-6">
        {/* TAB 1: SUMMARY & CORE FINDINGS */}
        {activeTab === "summary" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-[11px] font-mono text-slate-400">ANALYSIS TARGET</span>
                <p className="text-sm font-mono font-bold text-slate-200 mt-1 uppercase">
                  {analysis.analysis_type}
                </p>
                <p className="text-xs font-mono text-slate-500 truncate mt-0.5">
                  {analysis.original_filename || "Direct Payload"}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-[11px] font-mono text-slate-400">TARGET SHA-256</span>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-xs font-mono text-slate-300 truncate max-w-[200px]">
                    {analysis.input_hash || "N/A"}
                  </span>
                  {analysis.input_hash && (
                    <button
                      onClick={() => copyToClipboard(analysis.input_hash!, "input_hash")}
                      className="p-1 text-slate-400 hover:text-cyan-400"
                      title="Copy Hash"
                    >
                      {copiedKey === "input_hash" ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  )}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-[11px] font-mono text-slate-400">EVALUATION CONFIDENCE</span>
                <p className="text-sm font-mono font-bold text-slate-200 mt-1 uppercase">
                  {analysis.evidence_strength}
                </p>
                <p className="text-xs font-mono text-slate-500 mt-0.5">
                  {findings.length} findings correlated
                </p>
              </div>
            </div>

            {/* Findings preview */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                Triggered Detection Findings
              </h3>
              {findings.length > 0 ? (
                <div className="space-y-3">
                  {findings.map((f, i) => (
                    <div
                      key={i}
                      className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2 text-xs font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-bold">
                            {f.rule_id}
                          </span>
                          <span className="font-bold text-slate-100">{f.rule_name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-400 uppercase">{f.severity}</span>
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-amber-300 font-bold">
                            +{f.score_contribution} pts
                          </span>
                        </div>
                      </div>
                      <p className="text-slate-300 leading-relaxed">{f.explanation}</p>
                      <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800/80 text-slate-400 break-all">
                        <strong className="text-slate-300">Observed Evidence:</strong> {f.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-6 text-center text-xs font-mono text-slate-500">
                  No threat rules triggered. The message exhibited no malicious characteristics.
                </div>
              )}
            </div>

            {/* Limitations Notice */}
            {analysis.limitations && analysis.limitations.length > 0 && (
              <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-xs font-mono space-y-1">
                <span className="font-bold text-slate-400">ANALYSIS SCOPE & LIMITATIONS:</span>
                <ul className="list-disc list-inside text-slate-500 space-y-0.5 pl-1">
                  {analysis.limitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: HEADERS */}
        {activeTab === "headers" && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-6">
            <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
              Email Header Inspection & Sender Provenance
            </h3>

            {/* Header Fields Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  <tr>
                    <td className="py-2.5 px-3 text-slate-400 font-bold w-48">FROM:</td>
                    <td className="py-2.5 px-3 font-semibold text-slate-100">{header.from || "N/A"}</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 text-slate-400 font-bold">REPLY-TO:</td>
                    <td className="py-2.5 px-3">
                      {header.reply_to ? (
                        <span
                          className={
                            header.from_address &&
                            header.reply_to &&
                            header.from_address !== header.reply_to
                              ? "text-rose-400 font-bold"
                              : "text-slate-200"
                          }
                        >
                          {header.reply_to}
                        </span>
                      ) : (
                        <span className="text-slate-500">Not Specified</span>
                      )}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 text-slate-400 font-bold">RETURN-PATH:</td>
                    <td className="py-2.5 px-3 text-slate-300">{header.return_path || "N/A"}</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 text-slate-400 font-bold">SENDER DOMAIN:</td>
                    <td className="py-2.5 px-3 font-bold text-cyan-400">
                      {header.sender_domain || "N/A"}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 text-slate-400 font-bold">SUBJECT:</td>
                    <td className="py-2.5 px-3 text-slate-100">{header.subject || "N/A"}</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 text-slate-400 font-bold">DATE:</td>
                    <td className="py-2.5 px-3 text-slate-300">{header.date || "N/A"}</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 text-slate-400 font-bold">MESSAGE-ID:</td>
                    <td className="py-2.5 px-3 text-slate-400 truncate max-w-lg">
                      {header.message_id || "N/A"}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Authentication Headers & Provenance */}
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
              <span className="text-xs font-mono font-bold text-slate-300 uppercase">
                Authentication Headers & Verification Note
              </span>
              <p className="text-xs font-mono text-slate-400">{header.auth_note}</p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-500">SPF CLAIM:</span>
                  <p className="font-bold text-slate-200 mt-1 uppercase">{header.spf || "Not Present"}</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-500">DKIM CLAIM:</span>
                  <p className="font-bold text-slate-200 mt-1 uppercase">{header.dkim || "Not Present"}</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-500">DMARC CLAIM:</span>
                  <p className="font-bold text-slate-200 mt-1 uppercase">{header.dmarc || "Not Present"}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: BODY */}
        {activeTab === "body" && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                Sanitized Plain-Text Email Body
              </h3>
              <span className="text-xs font-mono text-slate-500">
                Untrusted HTML is never rendered in the client interface.
              </span>
            </div>
            {analysis.body_analysis?.text ? (
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed max-h-[500px] overflow-y-auto">
                {analysis.body_analysis.text}
              </pre>
            ) : (
              <p className="text-xs font-mono text-slate-500 py-6 text-center">
                No email body content available.
              </p>
            )}
          </div>
        )}

        {/* TAB 4: URLS */}
        {activeTab === "urls" && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                Extracted URLs & Structural Characteristics
              </h3>
              <span className="text-xs font-mono text-slate-500">
                Non-connecting static analysis
              </span>
            </div>

            {urls.length > 0 ? (
              <div className="space-y-4">
                {urls.map((u, i) => (
                  <div
                    key={i}
                    className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3 text-xs font-mono"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <span className="text-cyan-400 font-bold break-all">{u.original_url}</span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-amber-300 font-semibold self-start sm:self-auto">
                        Risk: +{u.risk_contribution}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-slate-400 bg-slate-900/60 p-2.5 rounded-lg">
                      <div>
                        <span>Host:</span>{" "}
                        <strong className="text-slate-200">{u.hostname || "N/A"}</strong>
                      </div>
                      <div>
                        <span>IP Host:</span>{" "}
                        <strong className={u.ip_host ? "text-rose-400" : "text-slate-200"}>
                          {u.ip_host ? "YES" : "NO"}
                        </strong>
                      </div>
                      <div>
                        <span>Shortener:</span>{" "}
                        <strong className={u.shortener ? "text-amber-400" : "text-slate-200"}>
                          {u.shortener ? "YES" : "NO"}
                        </strong>
                      </div>
                      <div>
                        <span>Port:</span>{" "}
                        <strong className={u.unusual_port ? "text-amber-400" : "text-slate-200"}>
                          {u.port || "Default"}
                        </strong>
                      </div>
                    </div>

                    {u.findings && u.findings.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-slate-400 font-bold">Findings:</span>
                        <ul className="list-disc list-inside text-amber-300/90 pl-1 space-y-0.5">
                          {u.findings.map((f: string, idx: number) => (
                            <li key={idx}>{f}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs font-mono text-slate-500 py-6 text-center">
                No URLs were detected in this message.
              </p>
            )}
          </div>
        )}

        {/* TAB 5: ATTACHMENTS */}
        {activeTab === "attachments" && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
              Attachment Artifacts & Hash Inspection
            </h3>
            {attachments.length > 0 ? (
              <div className="space-y-4">
                {attachments.map((att, i) => (
                  <div
                    key={i}
                    className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3 text-xs font-mono"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Paperclip className="w-4 h-4 text-cyan-400" />
                        <span className="font-bold text-slate-100">{att.filename}</span>
                      </div>
                      <span className="text-slate-400">
                        {att.size_bytes ? `${(att.size_bytes / 1024).toFixed(1)} KB` : "0 B"}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 bg-slate-900/60 p-2.5 rounded-lg text-[11px] text-slate-400">
                      <div>
                        <span>Extension:</span>{" "}
                        <strong className="text-slate-200">{att.extension || "N/A"}</strong>
                      </div>
                      <div>
                        <span>Reported MIME:</span>{" "}
                        <strong className="text-slate-200">{att.reported_mime || "N/A"}</strong>
                      </div>
                      <div>
                        <span>Detected Magic:</span>{" "}
                        <strong className="text-slate-200">{att.detected_type || "None"}</strong>
                      </div>
                    </div>

                    <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 truncate max-w-xl">
                        <strong className="text-slate-300">SHA-256:</strong> {att.sha256}
                      </span>
                      <button
                        onClick={() => copyToClipboard(att.sha256, `att_${i}`)}
                        className="p-1 text-slate-400 hover:text-cyan-400"
                        title="Copy SHA-256"
                      >
                        {copiedKey === `att_${i}` ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>

                    {att.signature_mismatch && (
                      <div className="p-2.5 rounded bg-rose-950/40 border border-rose-800/60 text-rose-300 font-bold">
                        SIGNATURE MISMATCH: File extension does not match magic byte signature!
                      </div>
                    )}

                    {att.archive && (
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-1">
                        <span className="text-slate-400 font-bold">Archive Inspection:</span>
                        <p className="text-slate-300">
                          Entries count: {att.archive.total_entries || 0}
                        </p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs font-mono text-slate-500 py-6 text-center">
                No attachments found in this email.
              </p>
            )}
          </div>
        )}

        {/* TAB 6: FINDINGS */}
        {activeTab === "findings" && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
              Full Evidence & Detection Rule Matrix
            </h3>
            {findings.length > 0 ? (
              <div className="space-y-4">
                {findings.map((f, i) => (
                  <div
                    key={i}
                    className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-cyan-400">
                        {f.rule_id} — {f.rule_name}
                      </span>
                      <span className="text-amber-400 font-bold">
                        Contribution: +{f.score_contribution}
                      </span>
                    </div>
                    <p className="text-slate-300">{f.explanation}</p>
                    <p className="text-slate-400">
                      <strong className="text-slate-300">Observed Evidence:</strong> {f.evidence}
                    </p>
                    <p className="text-slate-400">
                      <strong className="text-slate-300">Suggested Action:</strong>{" "}
                      {f.suggested_response}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs font-mono text-slate-500 py-6 text-center">
                No detection rules were triggered.
              </p>
            )}
          </div>
        )}

        {/* TAB 7: IOCS */}
        {activeTab === "iocs" && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
                Indicators of Compromise (IoCs)
              </h3>
              <a
                href={getExportUrl(analysis.id, "csv")}
                download={`iocs-${analysis.id}.csv`}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <Download className="w-3 h-3" /> Export CSV
              </a>
            </div>

            {indicators.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3">TYPE</th>
                      <th className="py-2.5 px-3">INDICATOR VALUE</th>
                      <th className="py-2.5 px-3">PROVENANCE</th>
                      <th className="py-2.5 px-3">STATUS</th>
                      <th className="py-2.5 px-3 text-right">COPY</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {indicators.map((ioc, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/20">
                        <td className="py-2.5 px-3 font-bold text-cyan-400 uppercase">
                          {ioc.indicator_type}
                        </td>
                        <td className="py-2.5 px-3 max-w-md truncate text-slate-200 font-mono">
                          {ioc.value}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">{ioc.provenance}</td>
                        <td className="py-2.5 px-3">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px] uppercase">
                            {ioc.verification_status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() => copyToClipboard(ioc.value, `ioc_${idx}`)}
                            className="p-1 text-slate-400 hover:text-cyan-400"
                            title="Copy value"
                          >
                            {copiedKey === `ioc_${idx}` ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-xs font-mono text-slate-500 py-6 text-center">
                No Indicators of Compromise extracted for this record.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
