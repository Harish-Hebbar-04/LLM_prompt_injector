"""detector.py

3-Layer Prompt Injection Detector

Layer 1 — Rule-Based Detection (Keyword Matching)
Algorithm: Aho–Corasick string matching
- Matches many patterns simultaneously in one pass over the text.
- We build an automaton from patterns in rules.py and scan multiple text variants.
- Each matched pattern adds to a keyword risk score.

Layer 2 — NLP Semantic Classification
Algorithm: Transformer classifier (DeBERTa)
- Uses HuggingFace Transformers locally (no API key).
- Requested model: "deepset/deberta-v3-base-injection".
- Produces a confidence score for injection vs normal.

Important: If the model cannot be downloaded/loaded (offline, no torch, etc),
we degrade gracefully: NLP layer becomes unavailable and returns a neutral score.
The system remains fully functional using the other layers.

Layer 3 — Statistical Anomaly Detection
Algorithm: Z-score + Shannon entropy + repetition checks
- Z-score measures how abnormal the input length is compared to a baseline.
- Shannon entropy measures character randomness/obfuscation.
- Repetition checks catch spammy payloads like "!!!!" or repeated substrings.

The final risk score is fused in scorer.py.
"""

from __future__ import annotations

import base64
import math
import re
import string
import threading
import time
import urllib.parse
from dataclasses import dataclass
from html import unescape
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from rules import RULES


try:
    import ahocorasick  # type: ignore
except Exception as exc:  # pragma: no cover
    ahocorasick = None


# Transformers are optional at runtime (graceful fallback).
try:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

    _TRANSFORMERS_AVAILABLE = True
except Exception:  # pragma: no cover
    _TRANSFORMERS_AVAILABLE = False


_LEETSPEAK_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)


def _safe_str(text: Any) -> str:
    return "" if text is None else str(text)


def _normalize_basic(text: str) -> str:
    """Basic normalization used before matching.

    - Lowercase
    - Collapse whitespace
    - Remove zero-width chars
    """

    text = text.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text


_HIGH_RISK_TERMS = [
    "system prompt",
    "system prompts",
    "developer instructions",
    "system message",
    "ignore previous",
    "ignore all previous",
    "override",
    "bypass safety",
    "dan",
    "reveal",
    "confidential",
    "training data",
    "api key",
    "password",
    ".env",
]

_BENIGN_TASK_PHRASES = [
    "help me",
    "explain",
    "what is",
    "what's",
    "summarize",
    "write a",
    "how does",
    "can you",
]


def calibrate_semantic_score(
    text: str,
    nlp_score: float,
    keyword_score: float,
    anomaly_score: float,
) -> Tuple[float, Optional[str]]:
    """Calibrate the semantic (transformer) score to reduce false positives.

    Reality check: transformer injection classifiers can be overly sensitive on
    "instruction-like" benign prompts (especially multi-question task lists).

    We keep this calibration *conservative*:
    - Only applies when **Layer 1 finds no indicators** AND anomaly is low.
    - If any high-risk terms appear, we do NOT calibrate down.

    This preserves strong detection for classic injections (Layer 1) while
    improving UX for normal user requests.
    """

    t = _normalize_basic(_safe_str(text))
    nlp_score = float(np.clip(nlp_score, 0.0, 100.0))

    if keyword_score > 0 or anomaly_score >= 25:
        return (nlp_score, None)

    high_risk_hits = sum(1 for term in _HIGH_RISK_TERMS if term in t)
    if high_risk_hits > 0:
        return (nlp_score, None)

    benign_hits = sum(1 for phrase in _BENIGN_TASK_PHRASES if phrase in t)

    # If it looks like a benign multi-task prompt and other layers are quiet,
    # cap semantic risk so the final fusion doesn't wrongly label it suspicious.
    if benign_hits >= 2 and len(t) <= 1200:
        calibrated = min(nlp_score, 35.0)
        return (
            calibrated,
            "Semantic score calibrated down (benign task-like prompt; no rule/anomaly indicators).",
        )

    return (nlp_score, None)


def _maybe_base64_decode(candidate: str) -> Optional[str]:
    """Try decoding base64 if it looks plausible.

    This helps with the requirement "Handle encoded variants (base64...)".
    We keep it conservative to avoid wasting time decoding random text.
    """

    # Heuristic: base64 strings are mostly A–Z a–z 0–9 + / and may end with '=' padding.
    if len(candidate) < 16:
        return None
    if len(candidate) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", candidate):
        return None

    try:
        decoded = base64.b64decode(candidate, validate=True)
        # Require mostly printable to reduce false positives.
        decoded_text = decoded.decode("utf-8", errors="ignore")
        printable_ratio = sum(ch in string.printable for ch in decoded_text) / max(1, len(decoded_text))
        if printable_ratio < 0.85:
            return None
        return decoded_text
    except Exception:
        return None


def generate_text_variants(text: str) -> List[str]:
    """Generate multiple text variants to catch simple obfuscations.

    Variants include:
    - Raw normalized
    - URL-decoded
    - HTML entity decoded
    - Leetspeak-normalized
    - Base64-decoded chunks (when input looks like base64)

    We scan all variants with Aho–Corasick and merge matches.
    """

    raw = _safe_str(text)

    variants: List[str] = []
    variants.append(_normalize_basic(raw))

    try:
        variants.append(_normalize_basic(urllib.parse.unquote_plus(raw)))
    except Exception:
        pass

    try:
        variants.append(_normalize_basic(unescape(raw)))
    except Exception:
        pass

    variants.append(_normalize_basic(raw.translate(_LEETSPEAK_MAP)))

    # Attempt full-string base64 decode.
    b64_full = _maybe_base64_decode(raw.strip())
    if b64_full:
        variants.append(_normalize_basic(b64_full))

    # Attempt to find base64-like tokens inside the text and decode them.
    for token in re.findall(r"\b[A-Za-z0-9+/=]{16,}\b", raw):
        decoded = _maybe_base64_decode(token)
        if decoded:
            variants.append(_normalize_basic(decoded))

    # De-duplicate while preserving order
    seen = set()
    unique: List[str] = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


@dataclass
class RuleMatch:
    pattern: str
    weight: int
    attack_type: str


class RuleBasedDetector:
    """Layer 1 detector using Aho–Corasick."""

    def __init__(self) -> None:
        if ahocorasick is None:
            raise RuntimeError(
                "pyahocorasick is not available. Install backend requirements to enable Layer 1."
            )

        self._rules_by_pattern: Dict[str, Tuple[int, str]] = {
            r.pattern.lower(): (r.weight, r.attack_type) for r in RULES
        }

        automaton = ahocorasick.Automaton()
        for pat in self._rules_by_pattern.keys():
            automaton.add_word(pat, pat)
        automaton.make_automaton()
        self._automaton = automaton

    def scan(self, text: str) -> Tuple[float, str, List[RuleMatch]]:
        """Return (keyword_score_0_100, attack_type, matches)."""

        variants = generate_text_variants(text)
        matches: Dict[str, RuleMatch] = {}

        for variant in variants:
            for _end_index, pat in self._automaton.iter(variant):
                weight, attack_type = self._rules_by_pattern.get(pat, (0, "Direct Instruction Override"))
                matches[pat] = RuleMatch(pattern=pat, weight=weight, attack_type=attack_type)

        if not matches:
            return (0.0, "None", [])

        # Sum weights but cap at 100 (normalize to score space).
        total_weight = sum(m.weight for m in matches.values())
        keyword_score = float(min(100, total_weight))

        # Attack type = the type with max total matched weight.
        type_totals: Dict[str, int] = {}
        for m in matches.values():
            type_totals[m.attack_type] = type_totals.get(m.attack_type, 0) + m.weight
        attack_type = max(type_totals.items(), key=lambda kv: kv[1])[0]

        return (keyword_score, attack_type, sorted(matches.values(), key=lambda m: m.weight, reverse=True))


class SemanticDetector:
    """Layer 2 semantic classifier using HuggingFace Transformers."""

    def __init__(self, model_name: str = "deepset/deberta-v3-base-injection") -> None:
        self.model_name = model_name
        self.available = False
        self.state: str = "uninitialized"  # uninitialized | loading | ready | error
        self._pipe = None
        self._load_error: Optional[str] = None
        self._lock = threading.Lock()
        self._loading_thread: Optional[threading.Thread] = None

        if not _TRANSFORMERS_AVAILABLE:
            self._load_error = "transformers/torch not installed"
            self.state = "error"
            return

    def load(self) -> None:
        """Load the model synchronously.

        This may download weights the first time, so it can take a while.
        We keep it separate so the FastAPI app can start immediately.
        """

        with self._lock:
            if self.state in ("loading", "ready"):
                return
            if self.state == "error" and self._pipe is not None:
                return
            self.state = "loading"
            self._load_error = None

        try:
            tokenizer = AutoTokenizer.from_pretrained(self.model_name, use_fast=True)
            model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            pipe = pipeline(
                task="text-classification",
                model=model,
                tokenizer=tokenizer,
                top_k=None,
                truncation=True,
                max_length=512,
            )
            with self._lock:
                self._pipe = pipe
                self.available = True
                self.state = "ready"
        except Exception as exc:
            with self._lock:
                # Keep the app running even if the model can't be loaded.
                self._load_error = str(exc)
                self.available = False
                self._pipe = None
                self.state = "error"

    def load_async(self) -> None:
        """Start loading the model in a background thread (non-blocking)."""

        if self.state in ("loading", "ready"):
            return
        if not _TRANSFORMERS_AVAILABLE:
            return

        # Avoid starting multiple threads.
        with self._lock:
            if self._loading_thread and self._loading_thread.is_alive():
                return

            t = threading.Thread(target=self.load, daemon=True)
            self._loading_thread = t
            t.start()

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    def score(self, text: str) -> Tuple[float, str]:
        """Return (nlp_score_0_100, explanation_snippet)."""

        # Non-blocking: kick off model load and return neutral until ready.
        if not self.available or self._pipe is None:
            self.load_async()
            if self.state == "loading":
                return (50.0, "NLP model loading in background; using neutral semantic score for now.")
            return (50.0, "NLP model unavailable; using neutral semantic score.")

        # The pipeline returns list[dict] or list[list[dict]] depending on config.
        outputs = self._pipe(_safe_str(text))
        if isinstance(outputs, list) and outputs and isinstance(outputs[0], list):
            scores = outputs[0]
        elif isinstance(outputs, list):
            scores = outputs
        else:
            scores = []

        # Find the most likely label and try to map it.
        best = None
        for item in scores:
            if not isinstance(item, dict):
                continue
            if best is None or float(item.get("score", 0.0)) > float(best.get("score", 0.0)):
                best = item

        if not best:
            return (50.0, "NLP model returned no scores; using neutral semantic score.")

        label = str(best.get("label", ""))
        conf = float(best.get("score", 0.0))

        # Heuristic mapping: many injection models use labels containing "INJECTION", "MALICIOUS", "SAFE", "NORMAL".
        label_lower = label.lower()
        if any(token in label_lower for token in ("inject", "mal", "attack", "jailbreak")):
            inj_prob = conf
        elif any(token in label_lower for token in ("safe", "normal", "benign", "legit", "clean")):
            inj_prob = 1.0 - conf
        else:
            # Unknown label scheme; treat confidence as injection-leaning but softer.
            inj_prob = conf

        nlp_score = float(np.clip(inj_prob * 100.0, 0.0, 100.0))
        return (nlp_score, f"Transformer label={label} confidence={conf:.2f}")


def shannon_entropy(text: str) -> float:
    """Shannon entropy H(X) in bits/char.

    Higher entropy can indicate obfuscation or encoded payloads.
    """

    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return float(entropy)


def max_run_length(text: str) -> int:
    """Longest run of the same character (e.g., "!!!!!" => 5)."""

    if not text:
        return 0
    best = 1
    run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            run += 1
            best = max(best, run)
        else:
            run = 1
    return best


class AnomalyDetector:
    """Layer 3 anomaly detection (Z-score + entropy + repetition).

    Baseline (beginner-friendly):
    - We use fixed baseline length mean/std.
    - This avoids needing a database.

    You can improve later by learning baselines from your own traffic.
    """

    def __init__(self, length_mean: float = 220.0, length_std: float = 140.0) -> None:
        self.length_mean = float(length_mean)
        self.length_std = float(max(1.0, length_std))

    def score(self, text: str) -> Tuple[float, Dict[str, float]]:
        text = _safe_str(text)
        n = len(text)

        # Z-score for length.
        z = (n - self.length_mean) / self.length_std
        z_abs = abs(z)

        # Map z-score to 0..100. Around |z|>=3 is considered extreme.
        length_component = float(np.clip((z_abs / 3.0) * 100.0, 0.0, 100.0))

        # Entropy: typical English text is ~3.5-4.5 bits/char; random/base64 can be higher.
        ent = shannon_entropy(text)
        entropy_component = float(np.clip(((ent - 3.5) / 2.5) * 100.0, 0.0, 100.0))

        # Repetition: very long runs are suspicious.
        run = max_run_length(text)
        repetition_component = float(np.clip(((run - 6) / 20.0) * 100.0, 0.0, 100.0))

        # Special character ratio.
        specials = sum(1 for ch in text if ch in string.punctuation)
        special_ratio = specials / max(1, n)
        special_component = float(np.clip(((special_ratio - 0.12) / 0.38) * 100.0, 0.0, 100.0))

        # Combine anomaly sub-signals (simple average).
        anomaly = float(
            np.clip(
                (length_component + entropy_component + repetition_component + special_component) / 4.0,
                0.0,
                100.0,
            )
        )

        details = {
            "length_z": float(z),
            "entropy": float(ent),
            "max_run": float(run),
            "special_ratio": float(special_ratio),
        }
        return (anomaly, details)


class PromptInjectionDetector:
    """Orchestrates all layers and produces a unified result payload."""

    def __init__(self) -> None:
        self.rules = RuleBasedDetector()
        self.semantic = SemanticDetector()
        self.anomaly = AnomalyDetector()

    def detect(self, message: str) -> Dict[str, Any]:
        start = time.time()

        keyword_score, attack_type, matches = self.rules.scan(message)
        nlp_score, nlp_note = self.semantic.score(message)
        anomaly_score, anomaly_details = self.anomaly.score(message)

        nlp_score, calibration_note = calibrate_semantic_score(
            message,
            nlp_score,
            keyword_score=keyword_score,
            anomaly_score=anomaly_score,
        )

        # Explanation is user-facing: short, clear, and based on signals.
        match_summary = ", ".join([m.pattern for m in matches[:4]])
        explanation_parts: List[str] = []
        if keyword_score > 0:
            explanation_parts.append(f"Matched injection indicators: {match_summary}")
        if self.semantic.available:
            explanation_parts.append(f"Semantic model: {nlp_note}")
        else:
            explanation_parts.append(f"Semantic model unavailable: {nlp_note}")

        if calibration_note:
            explanation_parts.append(calibration_note)
        if anomaly_score >= 35:
            explanation_parts.append(
                f"Anomaly signals: entropy={anomaly_details['entropy']:.2f}, length_z={anomaly_details['length_z']:.2f}"
            )

        if not explanation_parts:
            explanation_parts.append("No strong injection indicators detected.")

        elapsed_ms = int((time.time() - start) * 1000)

        return {
            "attack_type": attack_type if attack_type != "None" else "None",
            "layer_scores": {
                "keyword_score": float(keyword_score),
                "nlp_score": float(nlp_score),
                "anomaly_score": float(anomaly_score),
            },
            "debug": {
                "matches": [m.__dict__ for m in matches[:10]],
                "anomaly_details": anomaly_details,
                "semantic_available": self.semantic.available,
                "semantic_load_error": self.semantic.load_error,
                "semantic_state": getattr(self.semantic, "state", "unknown"),
                "elapsed_ms": elapsed_ms,
            },
            "explanation": ". ".join(explanation_parts),
        }
