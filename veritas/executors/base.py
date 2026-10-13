"""执行器接口。

执行器把一个攻击机会（opportunity）落地，成功时返回对攻击图的"跃迁"
（新立足点/凭据/战利品/资产/漏洞）。"利用是否成功"由执行器确定性判定——
creative（solver 决策）与 deterministic（执行判定）分离。
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Transition:
    """执行成功后对攻击图的增量。"""
    footholds: list[dict] = field(default_factory=list)    # {label, access_level, location, props}
    credentials: list[dict] = field(default_factory=list)  # {kind, username, secret, source}
    loot: list[dict] = field(default_factory=list)         # {kind, summary, props}
    assets: list[dict] = field(default_factory=list)       # {type, dedup_key, reachable_from, props, in_scope}
    findings: list[dict] = field(default_factory=list)     # {type, severity, reproduction}


@dataclass
class ExecResult:
    success: bool
    summary: str
    transition: Transition = field(default_factory=Transition)


class Executor:
    kinds: tuple[str, ...] = ()

    async def execute(self, opp, board, task_id: str) -> ExecResult:  # pragma: no cover
        raise NotImplementedError
