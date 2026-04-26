"""main.py

FastAPI backend for the "LLM Prompt Injection Detector".

Endpoints:
1) POST /detect
   - Accepts: { "message": "..." }
   - Runs 3-layer detection engine
   - Returns risk_score, label, color, attack_type, explanation, layer_scores, action
   - Saves to logs.json if risk_score > 30

2) GET /logs
   - Returns last 20 flagged attempts

3) GET /stats
   - Returns totals: total_scanned, total_blocked, total_suspicious, total_safe

4) GET /health
   - Simple health check

Storage:
- No database. Uses a single flat JSON file: logs.json
- The file stores:
  - "events": flagged detections (score > 30)
  - "stats": counters for all scans

CORS:
- Enabled for http://localhost:3000 so React can call the API.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from detector import PromptInjectionDetector
from scorer import FusionWeights, label_for_score, weighted_average


APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "logs.json"

_file_lock = threading.Lock()

detector = PromptInjectionDetector()
weights = FusionWeights(keyword=0.40, nlp=0.45, anomaly=0.15)


class DetectRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=20_000)


def _default_store() -> Dict[str, Any]:
    return {
        "events": [],
        "stats": {
            "total_scanned": 0,
            "total_blocked": 0,
            "total_suspicious": 0,
            "total_safe": 0,
        },
    }


def _read_store() -> Dict[str, Any]:
    if not LOG_PATH.exists():
        return _default_store()

    try:
        raw = LOG_PATH.read_text(encoding="utf-8")
        data = json.loads(raw) if raw.strip() else _default_store()
        if "events" not in data or "stats" not in data:
            return _default_store()
        return data
    except Exception:
        return _default_store()


def _write_store(data: Dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = LOG_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    # On Windows, editors/AV scanners can briefly lock the destination file.
    # Retry atomic replace a few times to avoid 500 errors during /detect.
    for attempt in range(6):
        try:
            os.replace(tmp_path, LOG_PATH)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.10)


def _update_stats(store: Dict[str, Any], label: str, action: str) -> None:
    stats = store.get("stats", {})
    stats["total_scanned"] = int(stats.get("total_scanned", 0)) + 1
    if label == "SAFE":
        stats["total_safe"] = int(stats.get("total_safe", 0)) + 1
    elif label == "SUSPICIOUS":
        stats["total_suspicious"] = int(stats.get("total_suspicious", 0)) + 1
    elif label == "DANGEROUS":
        stats["total_blocked"] = int(stats.get("total_blocked", 0)) + 1

    # Treat "BLOCKED" as blocked, "FLAGGED" as suspicious, "ALLOWED" as safe.
    # (Label already covers this, but action is returned to UI.)
    store["stats"] = stats


app = FastAPI(title="LLM Prompt Injection Detector", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"] ,
    allow_headers=["*"] ,
)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "version": APP_VERSION,
        "nlp_model_loaded": bool(detector.semantic.available),
        "nlp_model_state": getattr(detector.semantic, "state", "unknown"),
        "nlp_model_name": detector.semantic.model_name,
        "nlp_load_error": detector.semantic.load_error,
    }


@app.on_event("startup")
def _warmup_semantic_model() -> None:
    # Non-blocking warm-up: downloads/loads the transformer in background.
    # The API remains responsive while the model loads.
    try:
        detector.semantic.load_async()
    except Exception:
        pass


@app.get("/stats")
def stats() -> Dict[str, Any]:
    with _file_lock:
        store = _read_store()
        return store.get("stats", _default_store()["stats"])


@app.get("/logs")
def logs() -> List[Dict[str, Any]]:
    with _file_lock:
        store = _read_store()
        events = store.get("events", [])
        # Return most recent first, max 20
        return list(reversed(events[-20:]))


@app.post("/detect")
def detect(req: DetectRequest) -> Dict[str, Any]:
    message = req.message

    detection = detector.detect(message)
    layer_scores = detection["layer_scores"]

    final_score = weighted_average(layer_scores, weights)
    label, color, action = label_for_score(final_score)

    # If we got no match-derived type but NLP is very high, classify as generic.
    attack_type = detection.get("attack_type") or "None"
    if attack_type == "None" and float(layer_scores.get("nlp_score", 0.0)) >= 75:
        attack_type = "Policy/Guardrail Bypass"

    result = {
        "message": message,
        "risk_score": int(round(final_score)),
        "label": label,
        "color": color,
        "attack_type": attack_type,
        "explanation": detection.get("explanation", ""),
        "layer_scores": {
            "keyword_score": int(round(layer_scores.get("keyword_score", 0))),
            "nlp_score": int(round(layer_scores.get("nlp_score", 0))),
            "anomaly_score": int(round(layer_scores.get("anomaly_score", 0))),
        },
        "action": action,
    }

    timestamp = int(time.time())

    # Save if score > 30 as requested.
    with _file_lock:
        store = _read_store()
        _update_stats(store, label=label, action=action)

        if result["risk_score"] > 30:
            store["events"].append(
                {
                    "ts": timestamp,
                    "message": message,
                    "risk_score": result["risk_score"],
                    "label": label,
                    "color": color,
                    "attack_type": attack_type,
                    "action": action,
                    "explanation": result["explanation"],
                }
            )
        try:
            _write_store(store)
        except PermissionError:
            # If logs.json is temporarily locked, don't fail detection.
            # The UI still gets the detection result; stats/logs may not persist for this request.
            pass

    return result


# Ensure logs.json exists on first run.
with _file_lock:
    if not LOG_PATH.exists():
        _write_store(_default_store())
