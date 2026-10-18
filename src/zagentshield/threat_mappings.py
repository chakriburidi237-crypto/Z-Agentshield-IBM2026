"""Documented taxonomy candidates for deterministic scanner indicators."""

RULE_MAPPINGS = {
    "PI-001": ({
        "framework": "OWASP Top 10 for LLM Applications",
        "version": "2025",
        "identifier": "LLM01",
        "title": "Prompt Injection",
        "evidence_url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "qualification": "Candidate mapping from instruction-override text; not proof of model compromise.",
    },),
    "PI-002": ({
        "framework": "OWASP Top 10 for LLM Applications",
        "version": "2025",
        "identifier": "LLM07",
        "title": "System Prompt Leakage",
        "evidence_url": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
        "qualification": "Candidate mapping from a request to disclose hidden instructions; no prompt is returned.",
    },),
    "EXFIL-001": ({
        "framework": "OWASP Top 10 for LLM Applications",
        "version": "2025",
        "identifier": "LLM02",
        "title": "Sensitive Information Disclosure",
        "evidence_url": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
        "qualification": "Candidate mapping from text requesting protected data transfer; no transfer is performed.",
    },),
    "EXEC-001": (
        {
            "framework": "OWASP Top 10 for LLM Applications",
            "version": "2025",
            "identifier": "LLM06",
            "title": "Excessive Agency",
            "evidence_url": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
            "qualification": "Candidate mapping from a command-execution request; no command is run.",
        },
        {
            "framework": "MITRE ATT&CK",
            "version": "Enterprise",
            "identifier": "T1059",
            "title": "Command and Scripting Interpreter",
            "evidence_url": "https://attack.mitre.org/techniques/T1059/",
            "qualification": "Technique candidate only; scanner text alone does not establish adversary behavior or attribution.",
        },
    ),
}


def mappings_for_rule(rule_id: str) -> tuple[dict[str, str], ...]:
    """Return documented candidate mappings for a detected rule identifier."""
    return RULE_MAPPINGS.get(rule_id, ())
