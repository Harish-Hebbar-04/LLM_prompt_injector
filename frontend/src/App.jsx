import React, { useEffect, useState } from "react";
import axios from "axios";

import ChatBox from "./components/ChatBox";
import RiskMeter from "./components/RiskMeter";
import ResultCard from "./components/ResultCard";
import LogsTable from "./components/LogsTable";

const API_BASE = "http://localhost:8000";

function statPill(label, value) {
  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-4">
      <div className="text-xs text-slate-400">{label}</div>
      <div className="text-lg font-semibold mt-1">{value}</div>
    </div>
  );
}

export default function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState({
    total_scanned: 0,
    total_blocked: 0,
    total_suspicious: 0,
    total_safe: 0,
  });
  const [refreshToken, setRefreshToken] = useState(0);
  const [error, setError] = useState(null);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/stats`);
      setStats(res.data);
    } catch {
      // Keep UI usable even if backend down.
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleCheck = async (message) => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.post(`${API_BASE}/detect`, { message });
      setResult(res.data);
      await fetchStats();
      setRefreshToken((t) => t + 1);
    } catch (e) {
      setError("Detection failed. Make sure backend is running on http://localhost:8000");
    } finally {
      setLoading(false);
    }
  };

  const score = result?.risk_score ?? 0;

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
          <div>
            <div className="text-2xl font-bold">LLM Prompt Injection Detector</div>
            <div className="text-slate-300 mt-1">
              Rule-based + Transformer semantic + anomaly scoring
            </div>
          </div>
          <div className="text-sm text-slate-400">
            Backend: <span className="text-slate-200">{API_BASE}</span>
          </div>
        </div>

        {/* Stats bar */}
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3">
          {statPill("Total Scanned", stats.total_scanned ?? 0)}
          {statPill("Total Blocked", stats.total_blocked ?? 0)}
          {statPill("Total Suspicious", stats.total_suspicious ?? 0)}
          {statPill("Total Safe", stats.total_safe ?? 0)}
        </div>

        {error && (
          <div className="mt-4 text-sm text-rose-200 bg-rose-500/10 border border-rose-700/40 rounded-xl p-4">
            {error}
          </div>
        )}

        <div className="mt-6 grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ChatBox onCheck={handleCheck} loading={loading} />

          <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5">
            <div className="text-lg font-semibold">Risk Meter</div>
            <div className="text-sm text-slate-300 mt-1">Live score (0–100)</div>
            <div className="mt-4">
              <RiskMeter score={score} />
            </div>
            <div className="mt-4 text-xs text-slate-400">
              🟢 0–30 SAFE • 🟡 31–70 SUSPICIOUS • 🔴 71–100 DANGEROUS
            </div>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4">
          <ResultCard result={result} />
          <LogsTable refreshToken={refreshToken} />
        </div>

        <div className="mt-8 text-xs text-slate-500">
          Logs are stored in backend/logs.json (flat file). No database required.
        </div>
      </div>
    </div>
  );
}
