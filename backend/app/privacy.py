import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PrivacyResult:
    value: str
    fields_masked: int


_PII_PATTERNS = (
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[EMAIL_MASKED]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_MASKED]"),
    (
        re.compile(
            r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\w)"
        ),
        "[PHONE_MASKED]",
    ),
)


def mask_pii(value: str) -> PrivacyResult:
    masked_value = value
    fields_masked = 0
    for pattern, replacement in _PII_PATTERNS:
        masked_value, replacements = pattern.subn(replacement, masked_value)
        fields_masked += replacements
    return PrivacyResult(value=masked_value, fields_masked=fields_masked)
