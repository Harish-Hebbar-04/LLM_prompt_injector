import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API_BASE = "http://localhost:8000";

function rowClass(color) {
  if (color === "green") return "border-emerald-900/40";
  if (color === "yellow") return "border-amber-900/40";
  if (color === "red") return "border-rose-900/40";
  return "border-slate-700";
}

function pillClass(color) {
  if (color === "green") return "bg-emerald-500/15 text-emerald-200 border-emerald-700/60";
  if (color === "yellow") return "bg-amber-400/15 text-amber-200 border-amber-700/60";
  if (color === "red") return "bg-rose-500/15 text-rose-200 border-rose-700/60";
  return "bg-slate-500/15 text-slate-200 border-slate-700/60";
}

function formatTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

function preview(msg) {
  if (!msg) return "";
  const clean = msg.replace(/\s+/g, " ").trim();
  return clean.length > 90 ? clean.slice(0, 90) + "…" : clean;
}

/**
 * LogsTable
 * - Shows past 20 flagged messages
 * - Auto-refresh every 10 seconds
 */
export default function LogsTable({ refreshToken }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get(`${API_BASE}/logs`);
      setLogs(Array.isArray(res.data) ? res.data : []);
    } catch (e) {
      setError("Failed to load logs. Is backend running on :8000?");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
    const id = setInterval(fetchLogs, 10000);
    return () => clearInterval(id);
  }, [fetchLogs]);

  // After each detection, parent increments refreshToken.
  useEffect(() => {
    fetchLogs();
  }, [refreshToken, fetchLogs]);

  const rows = useMemo(() => logs.slice(0, 20), [logs]);

  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-lg font-semibold">Flagged Attempts</div>
          <div className="text-sm text-slate-300 mt-1">Auto-refreshes every 10s • Last 20</div>
        </div>
        <button
          onClick={fetchLogs}
          className="px-3 py-2 rounded-lg bg-slate-900/60 border border-slate-700 hover:bg-slate-900 text-sm"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="mt-3 text-sm text-rose-200 bg-rose-500/10 border border-rose-700/40 rounded-lg p-3">
          {error}
        </div>
      )}

      <div className="mt-4 overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-slate-300">
              <th className="py-2 pr-4">Time</th>
              <th className="py-2 pr-4">Message Preview</th>
              <th className="py-2 pr-4">Score</th>
              <th className="py-2 pr-4">Attack Type</th>
              <th className="py-2 pr-0">Action</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <tr>
                <td className="py-4 text-slate-400" colSpan={5}>
                  Loading logs…
                </td>
              </tr>
            ) : rows.length === 0 ? (
              <tr>
                <td className="py-4 text-slate-400" colSpan={5}>
                  No flagged messages yet.
                </td>
              </tr>
            ) : (
              rows.map((r, idx) => (
                <tr key={idx} className={"border-t " + rowClass(r.color)}>
                  <td className="py-3 pr-4 whitespace-nowrap text-slate-300">{formatTime(r.ts)}</td>
                  <td className="py-3 pr-4 text-slate-100">{preview(r.message)}</td>
                  <td className="py-3 pr-4 whitespace-nowrap">
                    <span className={"px-2 py-1 rounded border text-xs " + pillClass(r.color)}>
                      {r.risk_score}
                    </span>
                  </td>
                  <td className="py-3 pr-4 text-slate-200">{r.attack_type || "—"}</td>
                  <td className="py-3 pr-0 whitespace-nowrap text-slate-200">{r.action || "—"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
