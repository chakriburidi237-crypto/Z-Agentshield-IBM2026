"""Explainable, deterministic prompt-risk checks (not a model-based detector)."""

from __future__ import annotations

from dataclasses import dataclass
import re


MAX_PROMPT_LENGTH = 10_000


@dataclass(frozen=True)
class PromptFinding:
    rule_id: str
    severity: str
    description: str
    matched_indicator: str
    risk_points: int


@dataclass(frozen=True)
class PromptScanResult:
    risk_score: int
    risk_level: str
    findings: tuple[PromptFinding, ...]


_RULES: tuple[tuple[str, str, str, int, re.Pattern[str]], ...] = (
    (
        "PI-001",
        "HIGH",
        "Attempts to override higher-priority instructions.",
        35,
        re.compile(
            r"\b(?:ignore|disregard|override|forget)\b.{0,80}\b"
            r"(?:previous|prior|system|developer)\b.{0,40}\b(?:instructions?|rules?|prompt)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "PI-002",
        "HIGH",
        "Requests disclosure of hidden system or developer instructions.",
        30,
        re.compile(
            r"\b(?:reveal|show|print|repeat|leak|expose)\b.{0,50}\b"
            r"(?:system|developer|hidden)\b.{0,30}\b(?:prompt|instructions?|message)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "EXFIL-001",
        "CRITICAL",
        "Requests transfer of credentials, secrets, or protected data.",
        45,
        re.compile(
            r"\b(?:send|upload|exfiltrate|forward|email|post)\b.{0,80}\b"
            r"(?:secrets?|credentials?|tokens?|private|confidential|customer data)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "EXEC-001",
        "HIGH",
        "Requests shell or command execution.",
        35,
        re.compile(
            r"\b(?:run|execute|invoke)\b.{0,50}\b"
            r"(?:shell|command|powershell|cmd(?:\.exe)?|terminal)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)


def scan_prompt(prompt: str) -> PromptScanResult:
    """Scan bounded text without storing or returning the supplied prompt."""
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("Prompt must be a non-empty string.")
    if len(prompt) > MAX_PROMPT_LENGTH:
        raise ValueError(f"Prompt must be at most {MAX_PROMPT_LENGTH} characters.")

    findings = []
    for rule_id, severity, description, points, pattern in _RULES:
        match = pattern.search(prompt)
        if match:
            findings.append(
                PromptFinding(
                    rule_id=rule_id,
                    severity=severity,
                    description=description,
                    matched_indicator="rule pattern matched; source text withheld",
                    risk_points=points,
                )
            )
    score = min(100, sum(finding.risk_points for finding in findings))
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 35 else "LOW"
    return PromptScanResult(score, level, tuple(findings))
