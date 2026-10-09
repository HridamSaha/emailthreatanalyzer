import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  UploadCloud,
  FileCode,
  Link2,
  Paperclip,
  AlertTriangle,
  FileText,
  ShieldAlert,
  ArrowRight,
  CheckCircle,
  HelpCircle,
} from "lucide-react";
import {
  analyzeEmailFile,
  analyzeRawEmail,
  analyzeUrl,
  analyzeAttachment,
} from "../services/api";

type AnalysisMode = "email_file" | "raw_email" | "url" | "attachment";

export const AnalyzePage: React.FC = () => {
  const navigate = useNavigate();
  const [mode, setMode] = useState<AnalysisMode>("email_file");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [rawText, setRawText] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (mode === "email_file" && !file.name.toLowerCase().endsWith(".eml")) {
        setError("Only .eml files are supported for full email analysis.");
        setSelectedFile(null);
        return;
      }
      if (file.size > 10 * 1024 * 1024) {
        setError("File exceeds 10MB upload limit.");
        setSelectedFile(null);
        return;
      }
      setError(null);
      setSelectedFile(file);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (mode === "email_file" && !file.name.toLowerCase().endsWith(".eml")) {
        setError("Only .eml files are supported for full email analysis.");
        return;
      }
      setError(null);
      setSelectedFile(file);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      let result;
      if (mode === "email_file") {
        if (!selectedFile) {
          throw new Error("Please select an .eml file to analyze.");
        }
        result = await analyzeEmailFile(selectedFile);
      } else if (mode === "raw_email") {
        if (!rawText.trim()) {
          throw new Error("Please paste raw RFC email headers and body.");
        }
        result = await analyzeRawEmail(rawText);
      } else if (mode === "url") {
        if (!urlInput.trim()) {
          throw new Error("Please enter an absolute URL (e.g., https://example.com/login).");
        }
        result = await analyzeUrl(urlInput.trim());
      } else if (mode === "attachment") {
        if (!selectedFile) {
          throw new Error("Please select an artifact file to inspect.");
        }
        result = await analyzeAttachment(selectedFile);
      }

      if (result && result.id) {
        navigate(`/analysis/${result.id}`);
      } else {
        throw new Error("Failed to obtain analysis result ID");
      }
    } catch (err: any) {
      setError(err.message || "Analysis request failed.");
      setLoading(false);
    }
  };

  // Sample templates for quick testing
  const loadSampleRaw = (type: "benign" | "mismatch" | "phish") => {
    if (type === "benign") {
      setRawText(
        `From: IT Support <support@contoso.example>\nTo: Employee <emp@contoso.example>\nSubject: Scheduled Network Maintenance\nDate: Fri, 09 Oct 2026 09:00:00 +0000\nContent-Type: text/plain; charset="utf-8"\n\nHello Team,\n\nPlease be advised that regular network maintenance will occur this Saturday at 22:00 UTC.\nNo action is required on your part.\n\nRegards,\nIT Operations`
      );
    } else if (type === "mismatch") {
      setRawText(
        `From: Security Team <security@contoso.example>\nReply-To: Verification <verify-reset@attacker-domain.xyz>\nReturn-Path: <bounce@unrelated-server.top>\nTo: Victim <victim@contoso.example>\nSubject: Urgent: Password Reset Required\nDate: Fri, 09 Oct 2026 10:00:00 +0000\nContent-Type: text/plain; charset="utf-8"\n\nYour workstation password expires in 2 hours. Reply immediately with your current password to retain access.`
      );
    } else {
      setRawText(
        `From: Microsoft 365 Center <admin@m1crosoft-auth.xyz>\nReply-To: Auth Portal <collector@untrusted-host.top>\nTo: Executive <exec@contoso.example>\nSubject: FINAL NOTICE: Immediate wire transfer & password verification\nDate: Fri, 09 Oct 2026 10:15:00 +0000\nContent-Type: text/plain; charset="utf-8"\n\nURGENT: Your bank transfer payment invoice was suspended. You must login immediately within 2 hours or your account will be closed.\nConfirm your credentials here:\nhttp://185.199.108.153:8080/portal-secure/login`
      );
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold font-mono tracking-tight text-slate-100">
          Analyze Suspicious Email & Artifacts
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Perform non-executing static inspection, MIME extraction, SHA-256 calculation, and explainable threat scoring.
        </p>
      </div>

      {/* Safety Warning */}
      <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/50 flex items-start gap-3 text-amber-300 text-xs font-mono">
        <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400 mt-0.5" />
        <div>
          <span className="font-bold">SECURITY NOTICE & PRIVACY SAFEGUARD:</span> All analysis is executed locally and statically. Extracted URLs are parsed lexically and are never visited or resolved over the network. Do not upload sensitive or classified information to external scanning services without explicit authorization.
        </div>
      </div>

      {/* Mode Selector Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-1.5 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs">
        <button
          type="button"
          onClick={() => {
            setMode("email_file");
            setSelectedFile(null);
            setError(null);
          }}
          className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg font-semibold transition-all ${
            mode === "email_file"
              ? "bg-cyan-600 text-white shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          <span>Upload .EML</span>
        </button>

        <button
          type="button"
          onClick={() => {
            setMode("raw_email");
            setError(null);
          }}
          className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg font-semibold transition-all ${
            mode === "raw_email"
              ? "bg-cyan-600 text-white shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>Paste Raw</span>
        </button>

        <button
          type="button"
          onClick={() => {
            setMode("url");
            setError(null);
          }}
          className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg font-semibold transition-all ${
            mode === "url"
              ? "bg-cyan-600 text-white shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <Link2 className="w-4 h-4" />
          <span>Analyze URL</span>
        </button>

        <button
          type="button"
          onClick={() => {
            setMode("attachment");
            setSelectedFile(null);
            setError(null);
          }}
          className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg font-semibold transition-all ${
            mode === "attachment"
              ? "bg-cyan-600 text-white shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <Paperclip className="w-4 h-4" />
          <span>Attachment</span>
        </button>
      </div>

      {/* Main Analysis Form Card */}
      <form onSubmit={handleSubmit} className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-6">
        {/* Mode: Email File (.eml) */}
        {mode === "email_file" && (
          <div className="space-y-4">
            <label htmlFor="email-file-input" className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Upload Standard RFC Email Message (.eml)
            </label>
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-xl p-8 text-center cursor-pointer transition-colors bg-slate-950/40 relative"
            >
              <input
                id="email-file-input"
                data-testid="email-file-input"
                type="file"
                accept=".eml,message/rfc822"
                onChange={handleFileChange}
                className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
              />
              <div className="flex flex-col items-center gap-2">
                <UploadCloud className="w-10 h-10 text-cyan-400" />
                <span className="text-sm font-mono text-slate-200 font-semibold">
                  {selectedFile ? selectedFile.name : "Drag & drop an .eml file here, or click to browse"}
                </span>
                <span className="text-xs font-mono text-slate-500">
                  Maximum file size: 10 MB. File structure and MIME headers will be verified.
                </span>
              </div>
            </div>
            {selectedFile && (
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs font-mono">
                <span className="text-slate-300 font-semibold">{selectedFile.name}</span>
                <span className="text-slate-500">{(selectedFile.size / 1024).toFixed(1)} KB</span>
              </div>
            )}
          </div>
        )}

        {/* Mode: Paste Raw */}
        {mode === "raw_email" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Paste RFC Email Content (Headers + Body)
              </label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => loadSampleRaw("benign")}
                  className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 bg-slate-800 px-2 py-0.5 rounded"
                >
                  Load Benign Sample
                </button>
                <button
                  type="button"
                  onClick={() => loadSampleRaw("mismatch")}
                  className="text-[11px] font-mono text-amber-400 hover:text-amber-300 bg-slate-800 px-2 py-0.5 rounded"
                >
                  Load Spoofed Sample
                </button>
                <button
                  type="button"
                  onClick={() => loadSampleRaw("phish")}
                  className="text-[11px] font-mono text-rose-400 hover:text-rose-300 bg-slate-800 px-2 py-0.5 rounded"
                >
                  Load Phishing Sample
                </button>
              </div>
            </div>
            <textarea
              rows={12}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="From: sender@domain.com&#10;To: recipient@domain.com&#10;Subject: Security Alert&#10;Date: Fri, 09 Oct 2026 10:00:00 +0000&#10;&#10;Email body content here..."
              className="w-full rounded-xl bg-slate-950/80 border border-slate-800 p-4 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500/80 leading-relaxed"
            />
          </div>
        )}

        {/* Mode: URL Only */}
        {mode === "url" && (
          <div className="space-y-4">
            <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Suspicious URL Target (Lexical & Structural Analysis Only)
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="http://185.199.108.153:8080/secure-login/auth"
                className="flex-1 rounded-xl bg-slate-950/80 border border-slate-800 px-4 py-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500/80"
              />
              <button
                type="button"
                onClick={() => setUrlInput("http://185.199.108.153:8443/invoice-login-secure/view")}
                className="px-3 py-2 rounded-xl bg-slate-800 text-[11px] font-mono text-slate-300 hover:text-white"
              >
                Sample IP URL
              </button>
            </div>
            <p className="text-xs font-mono text-slate-500">
              The engine evaluates host IP indicators, suspicious tokens, unusual ports, lookalike domains, and percent encodings without connecting to the destination.
            </p>
          </div>
        )}

        {/* Mode: Attachment Only */}
        {mode === "attachment" && (
          <div className="space-y-4">
            <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Upload Individual Artifact / Attachment
            </label>
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-xl p-8 text-center cursor-pointer transition-colors bg-slate-950/40 relative"
            >
              <input
                type="file"
                onChange={handleFileChange}
                className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
              />
              <div className="flex flex-col items-center gap-2">
                <Paperclip className="w-10 h-10 text-cyan-400" />
                <span className="text-sm font-mono text-slate-200 font-semibold">
                  {selectedFile ? selectedFile.name : "Select or drag any file to inspect"}
                </span>
                <span className="text-xs font-mono text-slate-500">
                  Calculates SHA-256, matches magic bytes against declared MIME type, and checks dangerous extension rules.
                </span>
              </div>
            </div>
            {selectedFile && (
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs font-mono">
                <span className="text-slate-300 font-semibold">{selectedFile.name}</span>
                <span className="text-slate-500">{(selectedFile.size / 1024).toFixed(1)} KB</span>
              </div>
            )}
          </div>
        )}

        {/* Error message */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Submit Button */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="submit"
            disabled={loading}
            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-500 text-white font-mono text-xs font-bold tracking-wider transition-all shadow-lg shadow-cyan-950/40"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                <span>RUNNING STATIC INSPECTION...</span>
              </>
            ) : (
              <>
                <span>EXECUTE THREAT ANALYSIS</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
