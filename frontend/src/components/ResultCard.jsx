import React from "react";

function badgeClass(color) {
  if (color === "green") return "bg-emerald-500/15 text-emerald-200 border-emerald-700/60";
  if (color === "yellow") return "bg-amber-400/15 text-amber-200 border-amber-700/60";
  if (color === "red") return "bg-rose-500/15 text-rose-200 border-rose-700/60";
  return "bg-slate-500/15 text-slate-200 border-slate-700/60";
}

function emojiForLabel(label) {
  if (label === "SAFE") return "🟢";
  if (label === "SUSPICIOUS") return "🟡";
  if (label === "DANGEROUS") return "🔴";
  return "";
}

export default function ResultCard({ result }) {
  if (!result) return null;

  const {
    risk_score,
    label,
    color,
    attack_type,
    explanation,
    layer_scores,
    action,
  } = result;

  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-lg font-semibold">Detection Result</div>
          <div className="text-sm text-slate-300 mt-1">
            {emojiForLabel(label)} <span className="font-medium">{label}</span> • Risk {risk_score}
          </div>
        </div>

        <div className={"px-3 py-1.5 rounded-lg text-xs border " + badgeClass(color)}>
          Action: <span className="font-semibold">{action}</span>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="bg-slate-900/40 border border-slate-700 rounded-lg p-4">
          <div className="text-sm text-slate-300">Attack Type</div>
          <div className="mt-1 font-semibold">{attack_type || "None"}</div>
        </div>

        <div className="bg-slate-900/40 border border-slate-700 rounded-lg p-4">
          <div className="text-sm text-slate-300">Explanation</div>
          <div className="mt-1 text-sm text-slate-100 leading-relaxed">
            {explanation || "No explanation available."}
          </div>
        </div>
      </div>

      <div className="mt-4 bg-slate-900/40 border border-slate-700 rounded-lg p-4">
        <div className="text-sm text-slate-300 mb-3">Layer Breakdown</div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="rounded-lg border border-slate-700 bg-slate-950/30 p-3">
            <div className="text-xs text-slate-400">Keyword Score</div>
            <div className="text-lg font-semibold">{layer_scores?.keyword_score ?? "—"}</div>
          </div>
          <div className="rounded-lg border border-slate-700 bg-slate-950/30 p-3">
            <div className="text-xs text-slate-400">NLP Score</div>
            <div className="text-lg font-semibold">{layer_scores?.nlp_score ?? "—"}</div>
          </div>
          <div className="rounded-lg border border-slate-700 bg-slate-950/30 p-3">
            <div className="text-xs text-slate-400">Anomaly Score</div>
            <div className="text-lg font-semibold">{layer_scores?.anomaly_score ?? "—"}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
