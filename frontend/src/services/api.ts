import type { AnalysisResult, DetectionRule, HistoryItem, Stats } from "../types/analysis";

const BASE_URL = "/api/v1";

export interface ListAnalysesResponse {
  total: number;
  page: number;
  page_size: number;
  items: HistoryItem[];
}

export interface ListAnalysesParams {
  q?: string;
  classification?: string;
  severity?: string;
  sort?: string;
  order?: "asc" | "desc";
  page?: number;
  page_size?: number;
}

export async function checkHealth(): Promise<{ status: string }> {
  const res = await fetch("/health");
  if (!res.ok) throw new Error("Service unavailable");
  return res.json();
}

export async function getStats(): Promise<Stats> {
  const res = await fetch(`${BASE_URL}/stats`);
  if (!res.ok) throw new Error("Failed to fetch dashboard statistics");
  return res.json();
}

export async function getAnalyses(params: ListAnalysesParams = {}): Promise<ListAnalysesResponse> {
  const query = new URLSearchParams();
  if (params.q) query.set("q", params.q);
  if (params.classification) query.set("classification", params.classification);
  if (params.severity) query.set("severity", params.severity);
  if (params.sort) query.set("sort", params.sort);
  if (params.order) query.set("order", params.order);
  if (params.page) query.set("page", params.page.toString());
  if (params.page_size) query.set("page_size", params.page_size.toString());

  const res = await fetch(`${BASE_URL}/analyses?${query.toString()}`);
  if (!res.ok) throw new Error("Failed to fetch analysis history");
  return res.json();
}

export async function getAnalysis(id: string): Promise<AnalysisResult> {
  const res = await fetch(`${BASE_URL}/analyses/${id}`);
  if (!res.ok) throw new Error("Analysis not found");
  return res.json();
}

export async function deleteAnalysis(id: string): Promise<{ status: string; id: string }> {
  const res = await fetch(`${BASE_URL}/analyses/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete analysis");
  return res.json();
}

export async function getRules(): Promise<DetectionRule[]> {
  const res = await fetch(`${BASE_URL}/rules`);
  if (!res.ok) throw new Error("Failed to fetch detection rules");
  return res.json();
}

export async function toggleRule(ruleId: string, enabled: boolean): Promise<{ rule_id: string; enabled: boolean }> {
  const res = await fetch(`${BASE_URL}/rules/${ruleId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  if (!res.ok) throw new Error("Failed to toggle rule");
  return res.json();
}

export async function analyzeEmailFile(file: File): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${BASE_URL}/analyze/email`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Analysis failed" }));
    throw new Error(errorData.detail || "Failed to analyze email file");
  }
  return res.json();
}

export async function analyzeRawEmail(raw: string): Promise<AnalysisResult> {
  const res = await fetch(`${BASE_URL}/analyze/raw`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Analysis failed" }));
    throw new Error(errorData.detail || "Failed to analyze raw email");
  }
  return res.json();
}

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  const res = await fetch(`${BASE_URL}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Analysis failed" }));
    throw new Error(errorData.detail || "Failed to analyze URL");
  }
  return res.json();
}

export async function analyzeAttachment(file: File): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${BASE_URL}/analyze/attachment`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Analysis failed" }));
    throw new Error(errorData.detail || "Failed to analyze attachment");
  }
  return res.json();
}

export function getPdfReportUrl(id: string): string {
  return `${BASE_URL}/analyses/${id}/report`;
}

export function getExportUrl(id: string, format: "json" | "csv" = "json"): string {
  return `${BASE_URL}/analyses/${id}/export?format=${format}`;
}
