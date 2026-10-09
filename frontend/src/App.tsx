import React from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Navbar } from "./components/Navbar";
import { DashboardPage } from "./pages/DashboardPage";
import { AnalyzePage } from "./pages/AnalyzePage";
import { ResultsPage } from "./pages/ResultsPage";
import { HistoryPage } from "./pages/HistoryPage";
import { RulesPage } from "./pages/RulesPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col bg-[#0a0e17] text-slate-100">
        <Navbar />
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/analyze" element={<AnalyzePage />} />
            <Route path="/analysis/:id" element={<ResultsPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
          </Routes>
        </main>
        <footer className="border-t border-slate-900 bg-slate-950/60 py-6 px-4 text-center text-xs font-mono text-slate-500">
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
            <span>EMAIL THREAT ANALYSIS & MALWARE DETECTION SYSTEM — v1.0.0</span>
            <span className="text-slate-600">STRICT STATIC HEURISTICS • AIR-GAPPED BY DESIGN</span>
          </div>
        </footer>
      </div>
    </BrowserRouter>
  );
}

export default App;

