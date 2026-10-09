import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Search,
  Filter,
  ArrowUpDown,
  Download,
  Trash2,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Inbox,
  CheckCircle,
} from "lucide-react";
import {
  getAnalyses,
  deleteAnalysis,
  getPdfReportUrl,
} from "../services/api";
import type { HistoryItem, Classification } from "../types/analysis";
import { ClassificationBadge } from "../components/ClassificationBadge";

export const HistoryPage: React.FC = () => {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [search, setSearch] = useState("");
  const [classification, setClassification] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [sortField, setSortField] = useState("created_at");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Delete modal state
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const fetchHistory = () => {
    setLoading(true);
    getAnalyses({
      q: search || undefined,
      classification: classification || undefined,
      severity: severity || undefined,
      sort: sortField,
      order: sortOrder,
      page,
      page_size: pageSize,
    })
      .then((res) => {
        setItems(res.items);
        setTotal(res.total);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to load analysis history");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchHistory();
  }, [page, pageSize, classification, severity, sortField, sortOrder]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const confirmDelete = async () => {
    if (!deletingId) return;
    setDeleteLoading(true);
    try {
      await deleteAnalysis(deletingId);
      setDeletingId(null);
      fetchHistory();
    } catch (err: any) {
      alert("Error deleting case: " + (err.message || "Unknown error"));
    } finally {
      setDeleteLoading(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-slate-100">
            Analysis Archive & Audit History
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Search, filter, export, and review previously processed email threat cases.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg self-start sm:self-auto">
          RECORD COUNT: <strong className="text-cyan-400">{total}</strong>
        </div>
      </div>

      {/* Filter and Search Bar Card */}
      <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by case ID, subject, sender domain, filename, or hash..."
              className="w-full rounded-xl bg-slate-950/80 border border-slate-800 pl-10 pr-4 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/80"
            />
          </div>

          {/* Classification Filter */}
          <select
            value={classification}
            onChange={(e) => {
              setClassification(e.target.value);
              setPage(1);
            }}
            className="rounded-xl bg-slate-950/80 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/80"
          >
            <option value="">All Classifications</option>
            <option value="safe">Safe</option>
            <option value="suspicious">Suspicious</option>
            <option value="malicious">Malicious</option>
            <option value="manual_review">Manual Review</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(1);
            }}
            className="rounded-xl bg-slate-950/80 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/80"
          >
            <option value="">All Severities</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
          </select>

          {/* Sort By */}
          <select
            value={`${sortField}:${sortOrder}`}
            onChange={(e) => {
              const [f, o] = e.target.value.split(":");
              setSortField(f);
              setSortOrder(o as any);
              setPage(1);
            }}
            className="rounded-xl bg-slate-950/80 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/80"
          >
            <option value="created_at:desc">Newest First</option>
            <option value="created_at:asc">Oldest First</option>
            <option value="risk_score:desc">Highest Risk Score</option>
            <option value="risk_score:asc">Lowest Risk Score</option>
          </select>

          <button
            type="submit"
            className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold"
          >
            Search
          </button>
        </form>
      </div>

      {/* History Table Card */}
      <div className="rounded-2xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        {loading ? (
          <div className="py-20 flex flex-col items-center justify-center gap-2">
            <div className="w-8 h-8 border-3 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
            <p className="text-xs font-mono text-slate-400">Loading cases...</p>
          </div>
        ) : items.length === 0 ? (
          <div className="py-16 text-center text-xs font-mono text-slate-500 space-y-2">
            <Inbox className="w-8 h-8 mx-auto text-slate-600" />
            <p>No matching analysis records found in database.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">DATE (UTC)</th>
                  <th className="py-3 px-4">CASE ID</th>
                  <th className="py-3 px-4">TARGET / SUBJECT</th>
                  <th className="py-3 px-4">SENDER DOMAIN</th>
                  <th className="py-3 px-4">CLASSIFICATION</th>
                  <th className="py-3 px-4">SCORE</th>
                  <th className="py-3 px-4 text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {items.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                      {item.created_at ? new Date(item.created_at).toLocaleString() : "N/A"}
                    </td>
                    <td className="py-3.5 px-4 font-bold text-slate-200">
                      <Link
                        to={`/analysis/${item.id}`}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline"
                      >
                        {item.id.slice(0, 8)}...
                      </Link>
                    </td>
                    <td className="py-3.5 px-4 max-w-xs truncate text-slate-100 font-semibold">
                      {item.subject || item.original_filename || `Target: ${item.analysis_type}`}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 truncate max-w-[150px]">
                      {item.sender_domain || "—"}
                    </td>
                    <td className="py-3.5 px-4">
                      <ClassificationBadge classification={item.classification} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 font-bold">
                      <span
                        className={
                          item.risk_score >= 60
                            ? "text-rose-400"
                            : item.risk_score >= 30
                            ? "text-amber-400"
                            : "text-emerald-400"
                        }
                      >
                        {item.risk_score}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          to={`/analysis/${item.id}`}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 transition-colors"
                          title="Open Case Details"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Link>
                        <a
                          href={getPdfReportUrl(item.id)}
                          download={`analysis-${item.id}.pdf`}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 transition-colors"
                          title="Download PDF Report"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </a>
                        <button
                          onClick={() => setDeletingId(item.id)}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 transition-colors"
                          title="Delete Case"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 border-t border-slate-800 bg-slate-950/40 text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <span>SHOWING:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="rounded bg-slate-900 border border-slate-800 px-2 py-1 text-slate-300"
            >
              <option value={10}>10</option>
              <option value={15}>15</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
            <span>ENTRIES PER PAGE</span>
          </div>

          <div className="flex items-center gap-3">
            <span>
              PAGE <strong>{page}</strong> OF <strong>{totalPages}</strong>
            </span>
            <div className="flex items-center gap-1">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Modal for Deletion */}
      {deletingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="max-w-md w-full p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-rose-400">
              <AlertTriangle className="w-6 h-6 flex-shrink-0" />
              <h3 className="text-base font-bold font-mono text-slate-100">Confirm Deletion</h3>
            </div>
            <p className="text-xs font-mono text-slate-300 leading-relaxed">
              Are you sure you want to permanently remove analysis record{" "}
              <strong className="text-rose-400 font-mono">{deletingId}</strong>? Associated
              findings and extracted indicators will also be purged.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setDeletingId(null)}
                disabled={deleteLoading}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                disabled={deleteLoading}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono font-bold"
              >
                {deleteLoading ? "Deleting..." : "Permanently Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
