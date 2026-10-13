"""验证层基座：三态结论 + validator 接口。

核心纪律（对应 DESIGN 哲学 #2/#3）：
- 验证是确定性代码，不经 LLM，LLM 永不自证；
- 目标自身的断言/回显永不作为证据——只认可复现的客观信号；
- 拿不到足够证据时返回 INSUFFICIENT，绝不猜成 CONFIRMED（精度优先）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    CONFIRMED = "confirmed"       # 有确定性证据
    REFUTED = "refuted"           # 确定性证据表明不存在
    INSUFFICIENT = "insufficient" # 证据不足（含依赖缺失、无出网等）


@dataclass
class ValidationResult:
    verdict: Verdict
    evidence: dict = field(default_factory=dict)
    reproduction: str = ""


class Validator:
    vuln_type: str = "base"

    async def validate(self, finding: dict, scope, oob) -> ValidationResult:  # pragma: no cover
        raise NotImplementedError
