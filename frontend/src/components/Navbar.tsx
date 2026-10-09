import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  ShieldAlert,
  LayoutDashboard,
  FileSearch,
  History,
  Sliders,
  BarChart3,
  Activity,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";
import { checkHealth } from "../services/api";

export const Navbar: React.FC = () => {
  const location = useLocation();
  const [isHealthy, setIsHealthy] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;
    const verify = () => {
      checkHealth()
        .then(() => {
          if (mounted) setIsHealthy(true);
        })
        .catch(() => {
          if (mounted) setIsHealthy(false);
        });
    };
    verify();
    const interval = setInterval(verify, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { to: "/", label: "Dashboard", icon: LayoutDashboard },
    { to: "/analyze", label: "Analyze", icon: FileSearch },
    { to: "/history", label: "History", icon: History },
    { to: "/rules", label: "Detection Rules", icon: Sliders },
    { to: "/analytics", label: "Analytics & Reports", icon: BarChart3 },
  ];

  return (
    <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/30 group-hover:border-cyan-400/60 transition-colors">
              <ShieldAlert className="w-6 h-6 text-cyan-400 group-hover:scale-105 transition-transform" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-wider text-slate-100 font-mono">
                  EMAIL THREAT ANALYSIS
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/50">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono tracking-wide">
                MALWARE & PHISHING STATIC DEFENSE
              </p>
            </div>
          </Link>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive =
                item.to === "/"
                  ? location.pathname === "/"
                  : location.pathname.startsWith(item.to);
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium tracking-wide transition-all ${
                    isActive
                      ? "bg-slate-800/90 text-cyan-300 border border-slate-700/80 shadow-sm"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/80"
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? "text-cyan-400" : "text-slate-400"}`} />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>

          {/* Engine Health Badge */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs font-mono">
              <Activity className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400 text-[11px]">ENGINE:</span>
              {isHealthy === null ? (
                <span className="flex items-center gap-1 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-slate-400 animate-pulse" />
                  CONNECTING
                </span>
              ) : isHealthy ? (
                <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  ONLINE
                </span>
              ) : (
                <span className="flex items-center gap-1.5 text-rose-400 font-semibold">
                  <AlertCircle className="w-3 h-3 text-rose-400" />
                  OFFLINE
                </span>
              )}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
