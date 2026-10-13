"""OOB 接口。真实实现（自托管 interactsh）后续接入；接口先稳定下来。"""
from __future__ import annotations

import uuid


class OOBProvider:
    async def new_token(self) -> tuple[str, str]:
        """返回 (token, 可注入的回连域名/URL)。"""
        raise NotImplementedError

    async def poll(self, token: str) -> bool:
        """是否收到过该 token 的带外交互（DNS/HTTP）。"""
        raise NotImplementedError


class NoopOOB(OOBProvider):
    """未配置带外时的占位：永远收不到交互，validator 据此返回 INSUFFICIENT 而非误判。"""
    available = False

    async def new_token(self) -> tuple[str, str]:
        t = uuid.uuid4().hex[:16]
        return t, f"{t}.oob.invalid"

    async def poll(self, token: str) -> bool:
        return False
