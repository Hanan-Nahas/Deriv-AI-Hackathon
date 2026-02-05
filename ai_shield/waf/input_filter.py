"""Input filtering and prompt attack detection for LLM traffic."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Pattern

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    """Result object returned by InputFilter scans."""

    is_safe: bool
    risk_score: float
    matches: List[str]
    reason: str


class InputFilter:
    """Detect prompt injections, jailbreaks, exfiltration and role override attempts."""

    def __init__(self) -> None:
        """Initialize attack patterns and compile regexes for performance."""
        patterns = [
            r"ignore\s+previous\s+instructions",
            r"ignore\s+all\s+rules",
            r"system\s*prompt",
            r"developer\s*message",
            r"reveal\s+hidden\s+prompt",
            r"show\s+your\s+instructions",
            r"jailbreak",
            r"DAN\s+mode",
            r"do\s+anything\s+now",
            r"role\s*:\s*system",
            r"you\s+are\s+now\s+admin",
            r"simulate\s+root\s+access",
            r"override\s+safety",
            r"disable\s+guardrails",
            r"bypass\s+content\s+policy",
            r"print\s+environment\s+variables",
            r"export\s+secrets",
            r"api[_\s-]?key",
            r"token\s+leak",
            r"password\s+dump",
            r"sql\s+injection",
            r"drop\s+table",
            r"<script>",
            r"base64\s+decode",
            r"prompt\s+injection",
            r"confidential\s+data",
            r"private\s+keys?",
            r"ssh-rsa",
            r"BEGIN\s+PRIVATE\s+KEY",
        ]
        self._patterns: List[Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in patterns]

    def scan(self, user_input: str) -> FilterResult:
        """Scan user prompt for malicious patterns.

        Args:
            user_input: Incoming natural language user prompt.

        Returns:
            A FilterResult with safety flag, score, and detections.
        """
        try:
            matched_patterns: List[str] = []
            for pattern in self._patterns:
                if pattern.search(user_input):
                    matched_patterns.append(pattern.pattern)

            risk_score = min(1.0, len(matched_patterns) * 0.2)
            is_safe = risk_score < 0.4
            reason = "Input accepted" if is_safe else "Potential prompt attack detected"

            logger.info(
                "Input scan complete: safe=%s risk=%.2f matches=%d",
                is_safe,
                risk_score,
                len(matched_patterns),
            )
            return FilterResult(
                is_safe=is_safe,
                risk_score=risk_score,
                matches=matched_patterns,
                reason=reason,
            )
        except Exception as exc:  # pragma: no cover - defensive runtime path
            logger.exception("Input filter failed: %s", exc)
            return FilterResult(
                is_safe=False,
                risk_score=1.0,
                matches=["input_filter_error"],
                reason="Input filtering error; blocked by default",
            )
