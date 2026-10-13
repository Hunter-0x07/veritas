"""L4 验证层：确定性 oracle，裁决候选 finding 的三态。"""
from .base import Validator, Verdict, ValidationResult
from .sqli import SqliValidator
from .xss import XssValidator


def build_registry() -> dict[str, Validator]:
    return {v.vuln_type: v for v in (SqliValidator(), XssValidator())}


__all__ = ["Validator", "Verdict", "ValidationResult", "build_registry"]
