"""Prompt injection detection using ML + heuristic patterns."""

import re
import json
import base64
from typing import Any

from app.models import AnalyzerResult

# ── Known prompt injection signatures ─────────────────────────────────

DIRECT_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|above|prior)", re.I),
    re.compile(r"forget\s+(all\s+)?(previous|above|prior)", re.I),
    re.compile(r"do\s+not\s+(follow|obey|adhere\s+to)", re.I),
    re.compile(r"you\s+are\s+(now|not\s+an?\s+AI|a\s+free)", re.I),
    re.compile(r"act\s+as\s+(if\s+you\s+are|an?\s+(unbiased|unrestricted|free))", re.I),
    re.compile(r"system\s+prompt\s*:?", re.I),
    re.compile(r"new\s+instructions?\s*:?\s*ignore", re.I),
    re.compile(r"override\s+(mode|protocol|safeguards?)", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"dan\b", re.I),  # "Do Anything Now"
    re.compile(r"role[_\s]?play", re.I),
]

# ── Character play / roleplay jailbreak patterns ──────────────────────
# Social engineering: user asks model to pretend to be someone/something else

CHARACTER_PLAY_PATTERNS: list[re.Pattern] = [
    re.compile(r"pretend\s+(to\s+)?be\s+(my|a|an)", re.I),
    re.compile(r"role[- ]?play\s+(as\s+)?", re.I),
    re.compile(r"act\s+(as|like|if)\s+(you\s+(were|are)|a|an)", re.I),
    re.compile(r"(imagine|picture)\s+(you'?re|you\s+are)", re.I),
    re.compile(r"(grandma|grandparent)\s*(tells?|story)", re.I),
    re.compile(r"(fictional|creative)\s+(story|scenario|writing)", re.I),
    re.compile(r"(just\s+)?(for\s+)?(fun|educational|research)\s*(purposes?)?\s*(only)?", re.I),
    re.compile(r"mond[ae]y\s+mode", re.I),
    re.compile(r"hypothetical\s+(scenario|situation|question)", re.I),
    re.compile(r"write\s+(me\s+)?a\s+(story|poem|scene)\s+about", re.I),
    re.compile(r"describe\s+a\s+scenario\s+where", re.I),
    re.compile(r"character\s+(you\s+)?(play|act)", re.I),
]

# ── Many-shot jailbreak — repeated Q&A patterns ──────────────────────
# Repeated examples overload the model's alignment

MANY_SHOT_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:Q|Question)\s*:.*\n\s*(?:A|Answer)\s*:", re.M),
    re.compile(r"(?:Example|Step|Round|Turn)\s+\d+\s*:.*\n\s*(?:Response|Reply|Output)\s*:", re.M),
    re.compile(r"(?:User|Human|H)\s*:.*\n\s*(?:Assistant|AI|A)\s*:", re.M),
]

# ── Token smuggling — splitting bad words across chars ────────────────
# Attackers split sensitive tokens to bypass keyword filters

TOKEN_SMUGGLING_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b[a-z]\s[a-z]\s[a-z]\s[a-z]\s[a-z]\b"),
    re.compile(r"(?:c\s+o\s+m\s+m\s+a\s+n\s*d|h\s+a\s+c\s+k|b\s+o\s+m\s+b)"),
    re.compile(r"(?:c\-o\-m\-m\-a\-n\-d|h\-a\-c\-k|b\-o\-m\-b|w\-e\-a\-p\-o\-n)"),
    re.compile(r"(?:c\.o\.m\.m\.a\.n\.d|h\.a\.c\.k)", re.I),
    re.compile(r"\w[\s;.\-/]\w[\s;.\-/]\w[\s;.\-/]\w[\s;.\-/]\w[\s;.\-/]\w"),
]

# ── DAN & advanced jailbreak variants ─────────────────────────────────
# Sophisticated jailbreak techniques

DAN_VARIANTS_PATTERNS: list[re.Pattern] = [
    re.compile(r"DAN\b", re.I),
    re.compile(r"do\s+anything\s+now", re.I),
    re.compile(r"unfiltered\s+(mode|response|output)", re.I),
    re.compile(r"uncensored\s+(mode|response)", re.I),
    re.compile(r"(no\s+)?(restrictions?|limits?|boundaries?|filter|rules?)\s*(apply|off|disabled)", re.I),
    re.compile(r"(ignore|bypass|override)\s+(safety|alignment|ethical|moral|guidelines?)", re.I),
    re.compile(r"you\s+(can|may)\s+(say|do|respond)\s+anything", re.I),
    re.compile(r"no\s+(censorship?|filtering|restrictions?)", re.I),
    re.compile(r"without\s+(refusing|denying|rejecting)", re.I),
    re.compile(r"(reveal|show|print|output|display)\s+(your\s+)?(system|inner|secret)", re.I),
    re.compile(r"(dev|devil|developer)\s+mode", re.I),
    re.compile(r"opposite\s+(mode|response)", re.I),
]

# ── Indirect injection / payload patterns ─────────────────────────────

SUSPICIOUS_JSON_KEYS: list[re.Pattern] = [
    re.compile(r"^prompt$", re.I),
    re.compile(r"^system[_-]?prompt$", re.I),
    re.compile(r"^instructions?$", re.I),
    re.compile(r"^context$", re.I),
    re.compile(r"^messages?$", re.I),
    re.compile(r"^tools?$", re.I),
    re.compile(r"^functions?$", re.I),
]

# ── Entropy / structure heuristics ────────────────────────────────────

# Thresholds tuned empirically
HIGH_ENTROPY_THRESHOLD = 4.5  # Shannon entropy per char
SUSPICIOUS_REPEAT_CHAR_RATIO = 0.6


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * (p and __import__("math").log2(p)) for p in prob)


def _score_direct_injection(body_str: str) -> tuple[int, list[str]]:
    """Check for known prompt injection phrases."""
    tags: list[str] = []
    for pattern in DIRECT_INJECTION_PATTERNS:
        if pattern.search(body_str):
            tags.append("prompt_injection_direct")
            break
    score = 60 if tags else 0
    return score, tags


def _score_character_play(body_str: str) -> tuple[int, list[str]]:
    """Detect social engineering via character/roleplay."""
    tags: list[str] = []
    for pattern in CHARACTER_PLAY_PATTERNS:
        if pattern.search(body_str):
            tags.append("jailbreak:character_play")
            break
    score = 40 if tags else 0
    return score, tags


def _score_many_shot(body_str: str) -> tuple[int, list[str]]:
    """Detect many-shot jailbreak — repeated Q&A examples."""
    tags: list[str] = []
    matches = 0
    for pattern in MANY_SHOT_PATTERNS:
        found = pattern.findall(body_str)
        matches += len(found)

    if matches >= 3:
        tags.append(f"jailbreak:many_shot:{matches}")
    elif matches >= 1:
        tags.append("jailbreak:many_shot_suspicious")

    score = min(50, matches * 15) if tags else 0
    return score, tags


def _score_token_smuggling(body_str: str) -> tuple[int, list[str]]:
    """Detect token smuggling — split bad words."""
    tags: list[str] = []
    for pattern in TOKEN_SMUGGLING_PATTERNS:
        if pattern.search(body_str):
            tags.append("jailbreak:token_smuggling")
            break
    score = 35 if tags else 0
    return score, tags


def _score_dan_variants(body_str: str) -> tuple[int, list[str]]:
    """Detect DAN and advanced jailbreak variants."""
    tags: list[str] = []
    for pattern in DAN_VARIANTS_PATTERNS:
        if pattern.search(body_str):
            tags.append("jailbreak:dan_variant")
            break
    score = 45 if tags else 0
    return score, tags


def _score_encoded_injection(body_str: str) -> tuple[int, list[str]]:
    """Decode base64/hex payloads and check for injection in decoded content."""
    tags: list[str] = []
    score = 0

    # Base64 decode and check — search for base64-like substrings (no anchors)
    b64_pattern = re.compile(
        r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})"
    )
    for b64_match in b64_pattern.finditer(body_str):
        try:
            decoded = base64.b64decode(b64_match.group()).decode("utf-8", errors="ignore")
            for pattern in DIRECT_INJECTION_PATTERNS + DAN_VARIANTS_PATTERNS:
                if pattern.search(decoded):
                    tags.append("encoded_injection:base64")
                    score += 40
                    break
        except Exception:
            continue

    # Hex decode and check — search for hex substrings
    hex_pattern = re.compile(r"(?:0x)?([0-9a-fA-F]{16,})")
    for hex_match in hex_pattern.finditer(body_str):
        try:
            hex_val = hex_match.group(1) if hex_match.group(0).startswith("0x") else hex_match.group(0)
            decoded = bytes.fromhex(hex_val).decode("utf-8", errors="ignore")
            for pattern in DIRECT_INJECTION_PATTERNS + DAN_VARIANTS_PATTERNS:
                if pattern.search(decoded):
                    tags.append("encoded_injection:hex")
                    score += 40
                    break
        except Exception:
            continue

    return score, tags


def _score_suspicious_keys(body: Any, depth: int = 0) -> tuple[int, list[str]]:
    """Recursively check JSON-like structures for suspicious keys."""
    if depth > 4:
        return 0, []
    tags: list[str] = []
    if isinstance(body, dict):
        for key in body:
            for pat in SUSPICIOUS_JSON_KEYS:
                if pat.search(str(key)):
                    tags.append("suspicious_key:" + str(key))
                    break
            sub_score, sub_tags = _score_suspicious_keys(body[key], depth + 1)
            tags.extend(sub_tags)
    elif isinstance(body, list):
        for item in body:
            sub_score, sub_tags = _score_suspicious_keys(item, depth + 1)
            tags.extend(sub_tags)

    score = min(30, len(tags) * 10) if tags else 0
    return score, tags


def _score_entropy_anomaly(body_str: str) -> tuple[int, list[str]]:
    """High entropy can indicate encoded injection payloads."""
    tags: list[str] = []
    # Split into tokens and check each
    tokens = re.split(r"\s+", body_str)
    high_entropy_tokens = 0
    for token in tokens:
        if len(token) > 20 and _shannon_entropy(token) > HIGH_ENTROPY_THRESHOLD:
            high_entropy_tokens += 1

    if high_entropy_tokens > 2:
        tags.append("high_entropy_payload")
    score = min(40, high_entropy_tokens * 10) if tags else 0
    return score, tags


def _score_repetitive_structure(body_str: str) -> tuple[int, list[str]]:
    """Detect repetitive patterns common in fuzzing / probing."""
    tags: list[str] = []
    # Check for repeated chars
    if len(body_str) > 50:
        for ch in set(body_str):
            ratio = body_str.count(ch) / len(body_str)
            if ratio > SUSPICIOUS_REPEAT_CHAR_RATIO and ch not in (" ", "\n", "\t", "{"):
                tags.append("repetitive_structure")
                break
    score = 20 if tags else 0
    return score, tags


class PromptInjectionAnalyzer:
    """Detects prompt injection attacks using ML heuristics and pattern matching."""

    name = "prompt_injection"

    async def analyze(
        self,
        body: dict[str, Any] | list[Any] | str | None,
        body_raw: str | None,
    ) -> AnalyzerResult:
        """Run all prompt injection checks and return aggregated result."""
        if body is None and body_raw is None:
            return AnalyzerResult(score=0, tags=[], confidence=0.0)

        body_str = body_raw or (json.dumps(body) if body else "")

        all_score = 0
        all_tags: list[str] = []

        # Build the parsed body for key scanning (only if body is a dict/list)
        parsed_body = body if isinstance(body, (dict, list)) else (
            json.loads(body) if isinstance(body, str) else None
        )

        checks: list[tuple[int, list[str]]] = [
            _score_direct_injection(body_str),
            _score_character_play(body_str),
            _score_many_shot(body_str),
            _score_token_smuggling(body_str),
            _score_dan_variants(body_str),
            _score_encoded_injection(body_str),
            _score_suspicious_keys(parsed_body),
            _score_entropy_anomaly(body_str),
            _score_repetitive_structure(body_str),
        ]

        for score, tags in checks:
            all_score += score
            all_tags.extend(tags)

        # Deduplicate
        all_tags = list(dict.fromkeys(all_tags))
        score = min(100, all_score)

        # Confidence: how many detection methods fired
        fired = sum(1 for s, _ in checks if s > 0)
        confidence = min(1.0, fired / len(checks))

        return AnalyzerResult(
            score=score,
            tags=all_tags,
            confidence=round(confidence, 2),
        )
