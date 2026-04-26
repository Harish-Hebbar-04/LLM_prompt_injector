import React from "react";

function bandForScore(score) {
  if (score <= 30) return { label: "SAFE", color: "green", emoji: "🟢" };
  if (score <= 70) return { label: "SUSPICIOUS", color: "yellow", emoji: "🟡" };
  return { label: "DANGEROUS", color: "red", emoji: "🔴" };
}

function barColorClass(color) {
  switch (color) {
    case "green":
      return "bg-emerald-500";
    case "yellow":
      return "bg-amber-400";
    case "red":
      return "bg-rose-500";
    default:
      return "bg-slate-500";
  }
}

/**
 * RiskMeter
 * - Animated progress bar from 0..100
 * - Color banded by score (SAFE/SUSPICIOUS/DANGEROUS)
 */
export default function RiskMeter({ score }) {
  const s = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
  const band = bandForScore(s);

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm text-slate-300">Risk score</div>
        <div className="text-sm font-semibold">
          <span className="mr-2">{band.emoji}</span>
          <span className="mr-2">{s}</span>
          <span
            className={
              "px-2 py-1 rounded text-xs border " +
              (band.color === "green"
                ? "border-emerald-600/50 text-emerald-200"
                : band.color === "yellow"
                ? "border-amber-600/50 text-amber-200"
                : "border-rose-600/50 text-rose-200")
            }
          >
            {band.label}
          </span>
        </div>
      </div>

      <div className="w-full h-3 rounded bg-slate-800 overflow-hidden border border-slate-700">
        <div
          className={
            "h-3 transition-all duration-700 ease-out " +
            barColorClass(band.color)
          }
          style={{ width: `${s}%` }}
        />
      </div>

      <div className="flex justify-between text-xs text-slate-400 mt-2">
        <span>0</span>
        <span>30</span>
        <span>70</span>
        <span>100</span>
      </div>
    </div>
  );
}
