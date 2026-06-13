"""Advanced obfuscation detection beyond regex — entropy, encoding, transformation analysis."""

import re
import json
import math
import string
from typing import Any

from app.models import AnalyzerResult

# ── Extended obfuscation patterns ─────────────────────────────────────

EXTENDED_OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # Base64 variants
    ("base64_standard", re.compile(r"^(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$"), 25),
    ("base64_urlsafe", re.compile(r"^(?:[A-Za-z0-9_-]{4}){2,}(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=|[A-Za-z0-9_-]{4})$"), 25),
    ("base64_short", re.compile(r"(?=[A-Za-z0-9+/]{30,}=?)[A-Za-z0-9+/]{30,}={0,2}"), 15),
    # Hex encoding
    ("hex_encoding", re.compile(r"(?:0x)?[0-9a-fA-F]{16,}"), 20),
    ("hex_ascii", re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}"), 25),
    # Unicode escapes
    ("unicode_escape", re.compile(r"\\u[0-9a-fA-F]{4}"), 20),
    ("unicode_wide", re.compile(r"\\U[0-9a-fA-F]{8}"), 25),
    # URL encoding
    ("url_encoding", re.compile(r"(?:%[0-9a-fA-F]{2}){5,}"), 15),
    # HTML entities
    ("html_entity", re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]{2,8});"), 15),
    # String reversal (common evasion)
    ("reverse_trojan", re.compile(r"(?:esrever|rav_hcet|rav_beautif|gra)\w*", re.I), 20),
    # SQL hex encoding
    ("sql_hex", re.compile(r"0x[0-9a-fA-F]{8,}"), 25),
    # JSFuck / Brainfuck-like
    ("jsfuck_like", re.compile(r"[][()!+]{20,}"), 30),
    # Octal encoding
    ("octal_escape", re.compile(r"\\[0-7]{3}"), 20),
    # Mixed encoding (multiple types in one string)
    ("mixed_encoding", re.compile(r"(?:%[0-9a-fA-F]{2}.*\\u[0-9a-fA-F]{4})|(?:\\x[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2})"), 35),
]

# ── Character frequency analysis ──────────────────────────────────────

# Normal text has roughly this distribution
EXPECTED_CHAR_RANGES = {
    "printable_ascii": (0.80, 1.0),
    "lowercase": (0.40, 0.80),
    "digits": (0.01, 0.20),
    "special_chars": (0.01, 0.15),
}

SUSPICIOUS_HIGH_ENTROPY_THRESHOLD = 4.0  # Shannon entropy
SUSPICIOUS_LOW_ENTROPY_THRESHOLD = 1.5   # Repeated single char


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _char_frequency_score(body_str: str) -> tuple[int, list[str]]:
    """Score based on character distribution anomalies."""
    if not body_str:
        return 0, []
    tags: list[str] = []

    total = len(body_str)
    if total < 10:
        return 0, []

    printable = sum(1 for c in body_str if c in string.printable)
    lower = sum(1 for c in body_str if c.islower())
    digits = sum(1 for c in body_str if c.isdigit())
    special = sum(1 for c in body_str if c in string.punctuation)

    p_printable = printable / total
    p_lower = lower / total
    p_digits = digits / total
    p_special = special / total

    anomalies = 0

    if not (EXPECTED_CHAR_RANGES["printable_ascii"][0] <= p_printable <= EXPECTED_CHAR_RANGES["printable_ascii"][1]):
        anomalies += 1
    if not (EXPECTED_CHAR_RANGES["lowercase"][0] <= p_lower <= EXPECTED_CHAR_RANGES["lowercase"][1]):
        anomalies += 1
    if p_digits > EXPECTED_CHAR_RANGES["digits"][1]:
        tags.append("high_digit_ratio")
        anomalies += 1
    if p_special > EXPECTED_CHAR_RANGES["special_chars"][1]:
        tags.append("high_special_char_ratio")
        anomalies += 1

    if anomalies >= 2:
        tags.append("char_frequency_anomaly")

    score = min(30, anomalies * 10)
    return score, tags


def _entropy_analysis(body_str: str) -> tuple[int, list[str]]:
    """Analyze string entropy — encoded payloads have distinct entropy signatures."""
    if not body_str:
        return 0, []
    tags: list[str] = []

    ent = _shannon_entropy(body_str)
    if ent > SUSPICIOUS_HIGH_ENTROPY_THRESHOLD:
        tags.append(f"high_entropy:{ent:.1f}")
    elif ent < SUSPICIOUS_LOW_ENTROPY_THRESHOLD and len(body_str) > 50:
        tags.append(f"low_entropy:{ent:.1f}")

    # Check entropy of individual tokens
    tokens = re.findall(r"\S+", body_str)
    high_ent_tokens = sum(1 for t in tokens if len(t) > 10 and _shannon_entropy(t) > SUSPICIOUS_HIGH_ENTROPY_THRESHOLD)
    if high_ent_tokens > 2:
        tags.append(f"multiple_high_entropy_tokens:{high_ent_tokens}")

    score = min(35, len(tags) * 15)
    return score, tags


def _detect_transform_chaining(body_str: str) -> tuple[int, list[str]]:
    """Detect multiple encoding layers — common in advanced evasion."""
    if not body_str:
        return 0, []
    tags: list[str] = []
    layers = 0

    # Check for nested encoding
    if re.search(r"%[0-9a-fA-F]{2}", body_str):
        layers += 1
        decoded = re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), body_str)
        if re.search(r"\\u[0-9a-fA-F]{4}", decoded) or re.search(r"\\x[0-9a-fA-F]{2}", decoded):
            layers += 1

    if re.search(r"\\u[0-9a-fA-F]{4}", body_str):
        layers += 1
        # Check for double-encoded unicode
        if re.search(r"%5c%75", body_str, re.I):
            layers += 2

    if re.search(r"&#\d+;", body_str):
        layers += 1

    if layers >= 2:
        tags.append(f"transform_chaining:{layers}")

    score = min(40, layers * 15)
    return score, tags


def _scan_recursive(obj: Any, depth: int = 0) -> tuple[int, list[str]]:
    """Recursively scan all string values in a nested structure."""
    if depth > 6:
        return 0, []
    all_score = 0
    all_tags: list[str] = []

    if isinstance(obj, str):
        for name, pattern, weight in EXTENDED_OBFUSCATION_PATTERNS:
            if pattern.search(obj):
                all_tags.append(f"obfuscation:{name}")
                all_score += weight
                break  # One match per string to avoid tag spam

        # Additional analysis for longer strings
        if len(obj) > 30:
            cf_score, cf_tags = _char_frequency_score(obj)
            all_score += cf_score
            all_tags.extend(cf_tags)
            e_score, e_tags = _entropy_analysis(obj)
            all_score += e_score
            all_tags.extend(e_tags)
            tc_score, tc_tags = _detect_transform_chaining(obj)
            all_score += tc_score
            all_tags.extend(tc_tags)

    elif isinstance(obj, dict):
        for key, value in obj.items():
            s, t = _scan_recursive(key, depth + 1)
            all_score += s
            all_tags.extend(t)
            s, t = _scan_recursive(value, depth + 1)
            all_score += s
            all_tags.extend(t)

    elif isinstance(obj, list):
        for item in obj:
            s, t = _scan_recursive(item, depth + 1)
            all_score += s
            all_tags.extend(t)

    return all_score, all_tags


class AdvancedObfuscationAnalyzer:
    """Detects obfuscated payloads using entropy, character frequency, and transform chaining."""

    name = "obfuscation_advanced"

    async def analyze(
        self,
        body: dict[str, Any] | list[Any] | str | None,
        body_raw: str | None,
    ) -> AnalyzerResult:
        """Run all advanced obfuscation checks."""
        total_score = 0
        all_tags: list[str] = []

        # Scan body structure recursively
        if body is not None:
            s, t = _scan_recursive(body)
            total_score += s
            all_tags.extend(t)

        # Also scan raw body for patterns that might be lost in JSON parse
        if body_raw:
            raw_score, raw_tags = _scan_recursive(body_raw)
            total_score += raw_score
            all_tags.extend(raw_tags)

            # Full raw analysis
            cf_score, cf_tags = _char_frequency_score(body_raw)
            total_score += cf_score
            all_tags.extend(cf_tags)

            e_score, e_tags = _entropy_analysis(body_raw)
            total_score += e_score
            all_tags.extend(e_tags)

        # Deduplicate
        all_tags = list(dict.fromkeys(all_tags))
        score = min(100, total_score)

        # Confidence based on total unique tags
        confidence = min(1.0, len(all_tags) / 8)

        return AnalyzerResult(
            score=score,
            tags=all_tags,
            confidence=round(confidence, 2),
        )
