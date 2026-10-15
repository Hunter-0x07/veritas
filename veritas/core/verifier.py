"""证据确定性验证层（防幻觉）。

v1 的确定性验证没白做——这里降级为 Executor 结果的"动作是否真成功"判定：被登记的
立足点/凭据必须有真实证据支撑，否则判 unverified，不计入访问进展（结论不误报）。

判定规则（live）：
  - 证据片段能溯源到真实 sandbox 输出（有意义 token 过半命中），或
  - 该立足点 location / 凭据 secret 出现在某条 rc=0 的真实命令里（如 ssh host 'id' 成功）。
mock 是模拟地真值 → 一律 verified；external/recon 是侦察地真值 → 恒 verified。
"""
from __future__ import annotations

import re

from .state import rank

VERIFIED = "verified"
UNVERIFIED = "unverified"
_MIN_TOK = 4          # 参与溯源的 token 最小长度
_MIN_COVER = 0.5      # token 命中比例阈值


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"\s+", text or "") if len(t) >= _MIN_TOK]


def _traceable(evidence: str, haystack: str) -> bool:
    toks = _tokens(evidence)
    if not toks:
        return False
    hit = sum(1 for t in set(toks) if t in haystack)
    return hit / len(set(toks)) >= _MIN_COVER


class Verifier:
    def __init__(self, mode: str = "mock"):
        self.mode = mode

    def _ok_outputs(self, traces: list[dict]) -> str:
        """所有真实 sandbox 输出拼成的干草堆。"""
        return "\n".join((t.get("out") or "") for t in traces)

    def _ok_commands(self, traces: list[dict]) -> str:
        """成功（rc=0）执行过的命令拼成的串，用于 location/secret 溯源。"""
        return "\n".join((t.get("exec") or "") for t in traces if t.get("rc") == 0)

    def foothold(self, access_level: str, location: str, evidence: str,
                 traces: list[dict]) -> str:
        if self.mode != "live":
            return VERIFIED
        if rank(access_level) <= rank("recon"):   # 侦察地真值
            return VERIFIED
        hay_out = self._ok_outputs(traces)
        hay_cmd = self._ok_commands(traces)
        if location and len(location) >= _MIN_TOK and location in hay_cmd:
            return VERIFIED                         # 真的在该 location 上成功跑过命令
        if _traceable(evidence, hay_out):
            return VERIFIED                         # 证据可溯源到真实输出
        return UNVERIFIED

    def credential(self, secret: str, username: str, traces: list[dict]) -> str:
        if self.mode != "live":
            return VERIFIED
        hay = self._ok_outputs(traces) + "\n" + self._ok_commands(traces)
        if secret and len(secret) >= _MIN_TOK and secret in hay:
            return VERIFIED
        if username and len(username) >= _MIN_TOK and username in hay:
            return VERIFIED
        return UNVERIFIED
