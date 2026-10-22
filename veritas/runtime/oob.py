"""带外交互（OOB）接口 —— Stage 3 Cut 2b 的地基（本刀只预埋接口，不实现监听）。

SSRF / XXE / 盲注（盲 SQLi、盲命令注入）的确定性证明靠【引擎自选的唯一回调被真打中】：
引擎给一个唯一 token + 回连域名/URL，注入目标，再 poll 是否收到过该 token 的 DNS/HTTP 交互。
只有目标真的发起了带外请求才可能命中——这是 proof-of-effect 在"盲"场景的形态。

接口借自归档 v1（archive/v1-validator/veritas/oob/base.py），抽象先稳定：
  new_token() -> (token, 可注入的回连域名/URL)
  poll(token) -> 是否收到过该 token 的带外交互
真实监听（自托管 DNS+HTTP，interactsh 式）在 Cut 2b 落 `InteractshOOB`/`SelfHostedOOB`。
未配 OOB 时用 NoopOOB（available=False）——SSRF 等探针据此返 inconclusive，诚实降级、绝不误判。
"""
from __future__ import annotations

import uuid


class OOBProvider:
    available: bool = False

    async def new_token(self) -> tuple[str, str]:
        """返回 (token, 可注入的回连域名/URL)。"""
        raise NotImplementedError

    async def poll(self, token: str) -> bool:
        """是否收到过该 token 的带外交互（DNS/HTTP）。"""
        raise NotImplementedError


class NoopOOB(OOBProvider):
    """未配置带外时的占位：永远收不到交互 → 依赖 OOB 的探针返 inconclusive 而非误判。"""
    available = False

    async def new_token(self) -> tuple[str, str]:
        t = "vz" + uuid.uuid4().hex[:16]
        return t, f"{t}.oob.invalid"

    async def poll(self, token: str) -> bool:
        return False
