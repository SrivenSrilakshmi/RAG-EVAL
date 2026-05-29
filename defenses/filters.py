import re
from dataclasses import dataclass
from typing import Tuple


SENSITIVE_PATTERNS = [
    re.compile(r"ACC-\d{4}-\d{4}", re.IGNORECASE),
    re.compile(r"\b\d{6}\b\s*(to|-)\s*\b\d{6}\b", re.IGNORECASE),
    re.compile(r"executive salary band", re.IGNORECASE),
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?(previous|prior) instructions", re.IGNORECASE),
    re.compile(r"developer (override|mode)", re.IGNORECASE),
    re.compile(r"reveal|disclose|print", re.IGNORECASE),
    re.compile(r"confidential|secret", re.IGNORECASE),
]


@dataclass(frozen=True)
class DefenseConfig:
    prompt_filtering: bool = False
    prompt_separation: bool = False
    output_redaction: bool = False


def apply_prompt_filter(user_prompt: str) -> Tuple[bool, str]:
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(user_prompt):
            return (
                False,
                "Request blocked by prompt filter because it matches an unsafe instruction pattern.",
            )
    return True, ""


def separated_prompt(system_prompt: str, user_prompt: str, context_block: str) -> str:
    return (
        "<SYSTEM>\n"
        f"{system_prompt}\n"
        "</SYSTEM>\n\n"
        "<USER>\n"
        f"{user_prompt}\n"
        "</USER>\n\n"
        "<CONTEXT>\n"
        f"{context_block}\n"
        "</CONTEXT>"
    )


def redact_output(text: str) -> str:
    redacted = text
    redacted = re.sub(r"ACC-\d{4}-\d{4}", "ACC-[REDACTED]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r"\b(\d{6})\b\s*(to|-)\s*\b(\d{6})\b",
        "[REDACTED-SALARY-RANGE]",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def contains_sensitive_content(text: str) -> bool:
    return any(pattern.search(text) for pattern in SENSITIVE_PATTERNS)
