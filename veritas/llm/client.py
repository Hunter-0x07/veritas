"""LLM 客户端：live 模式走 LiteLLM（多 provider），带成本累计。

GLM-5.3 经 OpenAI 兼容端点 + reasoning_effort（走 extra_body 最稳）。mock 模式不调本模块。
"""
from __future__ import annotations

import os
from typing import Any, Optional

from ..config import LLMCfg


class LLMClient:
    def __init__(self, cfg: LLMCfg):
        self.model = cfg.model
        self.api_base = cfg.api_base
        self.api_key = os.environ.get(cfg.api_key_env) if cfg.api_key_env else None
        self.reasoning_effort = cfg.reasoning_effort
        self.extra_body = cfg.extra_body
        self.cost_usd = 0.0
        self.tokens_in = 0
        self.tokens_out = 0

    async def chat(self, messages: list[dict], tools: Optional[list[dict]] = None) -> Any:
        import litellm  # 延迟导入：mock 模式无需安装即可跑

        kw: dict = {"model": self.model, "messages": messages}
        if tools:
            kw["tools"] = tools
            kw["tool_choice"] = "auto"
        if self.api_base:
            kw["api_base"] = self.api_base
        if self.api_key:
            kw["api_key"] = self.api_key
        if self.reasoning_effort:
            kw["reasoning_effort"] = self.reasoning_effort
        if self.extra_body:
            kw["extra_body"] = self.extra_body
        resp = await litellm.acompletion(**kw)
        try:
            self.cost_usd += float(litellm.completion_cost(resp) or 0.0)
        except Exception:  # noqa: BLE001
            pass
        try:  # litellm 对 glm-5.3 常算不出单价($0)，至少累计 token 用量
            u = resp.usage
            self.tokens_in += int(getattr(u, "prompt_tokens", 0) or 0)
            self.tokens_out += int(getattr(u, "completion_tokens", 0) or 0)
        except Exception:  # noqa: BLE001
            pass
        return resp.choices[0].message
