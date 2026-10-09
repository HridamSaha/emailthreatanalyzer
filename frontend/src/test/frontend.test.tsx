import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { ClassificationBadge } from "../components/ClassificationBadge";
import { ScoreGauge } from "../components/ScoreGauge";
import { DashboardPage } from "../pages/DashboardPage";
import { AnalyzePage } from "../pages/AnalyzePage";
import * as api from "../services/api";

vi.mock("../services/api");

describe("ClassificationBadge Component", () => {
  it("renders Safe badge correctly", () => {
    render(<ClassificationBadge classification="safe" />);
    expect(screen.getByText("Safe")).toBeInTheDocument();
  });

  it("renders Suspicious badge correctly", () => {
    render(<ClassificationBadge classification="suspicious" />);
    expect(screen.getByText("Suspicious")).toBeInTheDocument();
  });

  it("renders Malicious badge correctly", () => {
    render(<ClassificationBadge classification="malicious" />);
    expect(screen.getByText("Malicious")).toBeInTheDocument();
  });

  it("renders Manual Review badge correctly", () => {
    render(<ClassificationBadge classification="manual_review" />);
    expect(screen.getByText("Manual Review")).toBeInTheDocument();
  });
});

describe("ScoreGauge Component", () => {
  it("displays low risk for scores below 30", () => {
    render(<ScoreGauge score={15} />);
    expect(screen.getByText("15")).toBeInTheDocument();
    expect(screen.getByText("LOW RISK")).toBeInTheDocument();
  });

  it("displays medium risk for scores between 30 and 59", () => {
    render(<ScoreGauge score={45} />);
    expect(screen.getByText("45")).toBeInTheDocument();
    expect(screen.getByText("MEDIUM RISK")).toBeInTheDocument();
  });

  it("displays high risk for scores 60 and above", () => {
    render(<ScoreGauge score={85} />);
    expect(screen.getByText("85")).toBeInTheDocument();
    expect(screen.getByText("HIGH RISK")).toBeInTheDocument();
  });
});

describe("DashboardPage Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders empty state when total analyses is 0", async () => {
    vi.mocked(api.getStats).mockResolvedValueOnce({
      total: 0,
      safe: 0,
      suspicious: 0,
      malicious: 0,
      manual_review: 0,
      high_risk: 0,
      classification_distribution: {},
      recent: [],
      top_rules: [],
      recent_domains: [],
      recent_hashes: [],
      risk_trend: [],
    });

    render(
      <BrowserRouter>
        <DashboardPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("No Email Telemetry Recorded")).toBeInTheDocument();
    });
  });

  it("renders populated KPI metrics and recent analyses table", async () => {
    vi.mocked(api.getStats).mockResolvedValueOnce({
      total: 4,
      safe: 1,
      suspicious: 2,
      malicious: 1,
      manual_review: 0,
      high_risk: 1,
      classification_distribution: { safe: 1, suspicious: 2, malicious: 1 },
      recent: [
        {
          id: "test-uuid-1234",
          analysis_type: "email_file",
          original_filename: "suspicious.eml",
          subject: "Urgent Payment Request",
          sender_domain: "attacker.xyz",
          created_at: "2026-10-09T10:00:00Z",
          classification: "suspicious",
          risk_score: 45,
          severity: "medium",
          summary: "Suspicious email detected",
        },
      ],
      top_rules: [
        { rule_id: "EMAIL-001", rule_name: "Sender Identity Mismatch", count: 2 },
      ],
      recent_domains: [{ domain: "attacker.xyz", count: 1 }],
      recent_hashes: ["abcdef1234567890"],
      risk_trend: [{ date: "2026-10-09", avg_score: 45, count: 1 }],
    });

    render(
      <BrowserRouter>
        <DashboardPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Urgent Payment Request")).toBeInTheDocument();
      expect(screen.getByText("attacker.xyz")).toBeInTheDocument();
      expect(screen.getByText("45 / 100")).toBeInTheDocument();
    });
  });
});

describe("AnalyzePage Component", () => {
  it("renders mode tabs and switches between email and raw paste", () => {
    render(
      <BrowserRouter>
        <AnalyzePage />
      </BrowserRouter>
    );

    expect(screen.getByText("Upload .EML")).toBeInTheDocument();
    expect(screen.getByText("Paste Raw")).toBeInTheDocument();
    expect(screen.getByText("Analyze URL")).toBeInTheDocument();
    expect(screen.getByText("Attachment")).toBeInTheDocument();

    // Click Paste Raw
    fireEvent.click(screen.getByText("Paste Raw"));
    expect(screen.getByText("Load Benign Sample")).toBeInTheDocument();

    // Click sample button
    fireEvent.click(screen.getByText("Load Benign Sample"));
    const textarea = screen.getByPlaceholderText(/From: sender@domain.com/i) as HTMLTextAreaElement;
    expect(textarea.value).toContain("support@contoso.example");
  });

  it("validates file upload rejection of invalid extensions", () => {
    render(
      <BrowserRouter>
        <AnalyzePage />
      </BrowserRouter>
    );

    const file = new File(["dummy content"], "test.pdf", { type: "application/pdf" });
    const input = screen.getByTestId("email-file-input");
    fireEvent.change(input, { target: { files: [file] } });
    expect(screen.getByText(/Only .eml files are supported/i)).toBeInTheDocument();
  });
});
