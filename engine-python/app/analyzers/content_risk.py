"""Content risk analysis — SQL injection, XSS, path traversal, and anomalous payload patterns."""

import re
import json
from typing import Any

from app.models import AnalyzerResult

# ── SQL injection patterns ────────────────────────────────────────────

SQL_INJECTION_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("sql_union", re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.I), 30),
    ("sql_or_1_1", re.compile(r"""\bOR\s+['"]?\d['"]?\s*=\s*['"]?\d['"]?""", re.I), 25),
    ("sql_and_1_1", re.compile(r"""\bAND\s+['"]?\d['"]?\s*=\s*['"]?\d['"]?""", re.I), 25),
    ("sql_drop", re.compile(r"\bDROP\s+TABLE\b", re.I), 30),
    ("sql_delete", re.compile(r"\bDELETE\s+FROM\b", re.I), 25),
    ("sql_insert", re.compile(r"\bINSERT\s+INTO\b", re.I), 20),
    ("sql_update", re.compile(r"\bUPDATE\s+\w+\s+SET\b", re.I), 20),
    ("sql_alter", re.compile(r"\bALTER\s+TABLE\b", re.I), 25),
    ("sql_exec", re.compile(r"\bEXEC(?:UTE)?\s*\(?", re.I), 30),
    ("sql_exec_xp", re.compile(r"\bxp_cmdshell\b", re.I), 35),
    ("sql_information_schema", re.compile(r"\bINFORMATION_SCHEMA\b", re.I), 25),
    ("sql_sleep", re.compile(r"\bSLEEP\s*\(\s*\d+\s*\)", re.I), 25),
    ("sql_benchmark", re.compile(r"\bBENCHMARK\s*\(", re.I), 25),
    ("sql_pg_sleep", re.compile(r"\bpg_sleep\s*\(", re.I), 25),
    ("sql_comment", re.compile(r"(--|#|\\/\*)"), 10),  # SQL comment injection
]

# ── XSS patterns ──────────────────────────────────────────────────────

XSS_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("xss_script_tag", re.compile(r"<script[^>]*>.*?</script>", re.I | re.S), 35),
    ("xss_on_event", re.compile(r"\bon\w+\s*=\s*['\"][^'\"]*['\"]", re.I), 30),
    ("xss_javascript", re.compile(r"javascript\s*:", re.I), 25),
    ("xss_alert", re.compile(r"alert\s*\([^)]*\)", re.I), 25),
    ("xss_eval", re.compile(r"\beval\s*\([^)]*\)", re.I), 30),
    ("xss_document_write", re.compile(r"document\.write\s*\(", re.I), 25),
    ("xss_src_attr", re.compile(r"""src\s*=\s*['"]\s*(?:javascript|data:text|vbscript)""", re.I), 25),
    ("xss_data_uri", re.compile(r"data\s*:\s*(?:text/html|application/javascript)", re.I), 20),
    ("xss_inner_html", re.compile(r"\.innerHTML\s*=", re.I), 25),
    ("xss_window_location", re.compile(r"window\.location\s*=", re.I), 20),
    ("xss_document_cookie", re.compile(r"document\.cookie\b", re.I), 20),
    ("xss_onerror", re.compile(r"onerror\s*=", re.I), 25),
    ("xss_onload", re.compile(r"onload\s*=", re.I), 20),
]

# ── Path traversal patterns ───────────────────────────────────────────

PATH_TRAVERSAL_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("path_traversal_dotdot", re.compile(r"\.\.(?:[/\\]|%2f|%5c)", re.I), 25),
    ("path_traversal_etc", re.compile(r"/etc/(?:passwd|shadow|hosts|config)", re.I), 30),
    ("path_traversal_proc", re.compile(r"/proc/self/", re.I), 20),
    ("path_traversal_windows", re.compile(r"[a-zA-Z]:\\windows\\", re.I), 20),
    ("path_traversal_env", re.compile(r"/env\b", re.I), 15),
    ("path_traversal_encoded", re.compile(r"%2e%2e%2f|%2e%2e%5c", re.I), 30),
]

# ── Command injection patterns ────────────────────────────────────────

CMD_INJECTION_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("cmd_pipe", re.compile(r"(?<!\w)\|(?!\|)", re.I), 20),
    ("cmd_semicolon", re.compile(r";\s*(?:sh|bash|cmd|powershell|rm|ls|cat|id|whoami)", re.I), 30),
    ("cmd_backtick", re.compile(r"`[^`]+`"), 25),
    ("cmd_subshell", re.compile(r"\$\([^)]+\)"), 25),
    ("cmd_rm", re.compile(r"\brm\s+-[rf]", re.I), 25),
    ("cmd_wget_curl", re.compile(r"\b(?:wget|curl)\s+[-a-zA-Z]*https?://", re.I), 20),
    ("cmd_chmod", re.compile(r"\bchmod\s+\d{3,4}", re.I), 20),
    ("cmd_cat_etc", re.compile(r"\bcat\s+/etc/", re.I), 25),
    ("cmd_bash_i", re.compile(r"bash\s+-i\s+[>&]", re.I), 30),
    ("cmd_reverse_shell", re.compile(r"(?:nc|netcat|bash|sh)\s+-[eci]+\s+/", re.I), 35),
]

# ── SSRF patterns ─────────────────────────────────────────────────────

SSRF_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("ssrf_localhost", re.compile(r"https?://(?:(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]))", re.I), 25),
    ("ssrf_private_ip", re.compile(r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})"), 25),
    ("ssrf_metadata", re.compile(r"https?://(?:169\.254\.169\.254|metadata\.google\.internal)"), 35),
    ("ssrf_cloud_metadata", re.compile(r"(?:instance\-metadata|metadata/instance)"), 30),
]


def _scan_str(value: str) -> tuple[int, list[str]]:
    """Scan a single string value against all content risk patterns."""
    total_score = 0
    all_tags: list[str] = []

    for name, pattern, weight in SQL_INJECTION_PATTERNS:
        if pattern.search(value):
            all_tags.append(name)
            total_score += weight
            break  # Only one SQL tag per string

    for name, pattern, weight in XSS_PATTERNS:
        if pattern.search(value):
            all_tags.append(name)
            total_score += weight
            break

    for name, pattern, weight in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(value):
            all_tags.append(name)
            total_score += weight
            break

    for name, pattern, weight in CMD_INJECTION_PATTERNS:
        if pattern.search(value):
            all_tags.append(name)
            total_score += weight
            break

    for name, pattern, weight in SSRF_PATTERNS:
        if pattern.search(value):
            all_tags.append(name)
            total_score += weight
            break

    return total_score, all_tags


def _scan_recursive(obj: Any, depth: int = 0) -> tuple[int, list[str]]:
    """Recursively scan all string values in nested structure."""
    if depth > 6:
        return 0, []
    total_score = 0
    all_tags: list[str] = []

    if isinstance(obj, str):
        return _scan_str(obj)

    elif isinstance(obj, dict):
        for key, value in obj.items():
            # Scan keys too
            k_score, k_tags = _scan_str(str(key))
            total_score += k_score
            all_tags.extend(k_tags)
            v_score, v_tags = _scan_recursive(value, depth + 1)
            total_score += v_score
            all_tags.extend(v_tags)

    elif isinstance(obj, list):
        for item in obj:
            s, t = _scan_recursive(item, depth + 1)
            total_score += s
            all_tags.extend(t)

    return total_score, all_tags


# ── Body structure risk analysis ──────────────────────────────────────

BODY_STRUCTURE_RISK_SCORES: list[tuple[str, int]] = [
    # Excessively large array
    ("oversized_array", 15),
    # Too many keys
    ("excessive_keys", 10),
    # Extremely deep nesting
    ("deep_nesting", 20),
]


def _analyze_body_structure(body: Any) -> tuple[int, list[str]]:
    """Analyze structural properties for risk indicators."""
    tags: list[str] = []
    score = 0

    if isinstance(body, list) and len(body) > 500:
        tags.append("oversized_array")
        score += 15

    if isinstance(body, dict):
        if len(body) > 100:
            tags.append("excessive_keys")
            score += 10

    # Check depth
    def _depth(obj: Any, current: int = 0) -> int:
        if isinstance(obj, dict) and obj:
            return max(_depth(v, current + 1) for v in obj.values())
        if isinstance(obj, list) and obj:
            return max(_depth(item, current + 1) for item in obj)
        return current

    d = _depth(body)
    if d > 5:
        tags.append("deep_nesting")
        score += min(20, (d - 5) * 5)

    return score, tags


class ContentRiskAnalyzer:
    """Detects content-level threats: SQLi, XSS, path traversal, command injection, SSRF."""

    name = "content_risk"

    async def analyze(
        self,
        body: dict[str, Any] | list[Any] | str | None,
        body_raw: str | None,
    ) -> AnalyzerResult:
        """Run all content risk checks."""
        total_score = 0
        all_tags: list[str] = []

        # Recursive scan on body
        if body is not None:
            s, t = _scan_recursive(body)
            total_score += s
            all_tags.extend(t)

            bs, bt = _analyze_body_structure(body)
            total_score += bs
            all_tags.extend(bt)

        # Also scan raw body
        if body_raw:
            raw_score, raw_tags = _scan_str(body_raw)
            total_score += raw_score
            all_tags.extend(raw_tags)

        # Deduplicate
        all_tags = list(dict.fromkeys(all_tags))
        score = min(100, total_score)

        # Confidence: how many categories fired
        categories = {"sql": False, "xss": False, "path": False, "cmd": False, "ssrf": False}
        for tag in all_tags:
            if tag.startswith("sql_"):
                categories["sql"] = True
            elif tag.startswith("xss_"):
                categories["xss"] = True
            elif tag.startswith("path_"):
                categories["path"] = True
            elif tag.startswith("cmd_"):
                categories["cmd"] = True
            elif tag.startswith("ssrf_"):
                categories["ssrf"] = True

        fired = sum(1 for v in categories.values() if v)
        confidence = min(1.0, fired / len(categories))

        return AnalyzerResult(
            score=score,
            tags=all_tags,
            confidence=round(confidence, 2),
        )
