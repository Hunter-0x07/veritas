"""LLM 封装：live 模式走 LiteLLM（多 provider），带成本累计。

mock 模式下不调用本模块——planner/worker 走各自的规则分支。
真实的 tool-use 循环由 worker 组织，这里只提供一次 chat 原语。
"""
from __future__ import annotations

from typing import Any, Optional


class LLMClient:
    def __init__(self, model: str, api_base: Optional[str] = None, api_key: Optional[str] = None,
                 reasoning_effort: Optional[str] = None, extra_body: Optional[dict] = None):
        self.model = model
        self.api_base = api_base
        self.api_key = api_key
        self.reasoning_effort = reasoning_effort
        self.extra_body = extra_body
        self.cost_usd = 0.0

    async def chat(self, messages: list[dict], tools: Optional[list[dict]] = None) -> Any:
        import litellm  # 延迟导入：mock 模式无需安装即可跑

        kwargs: dict = {"model": self.model, "messages": messages}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if self.api_base:
            kwargs["api_base"] = self.api_base
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.reasoning_effort:
            kwargs["reasoning_effort"] = self.reasoning_effort
        if self.extra_body:
            kwargs["extra_body"] = self.extra_body
        resp = await litellm.acompletion(**kwargs)
        try:
            self.cost_usd += float(litellm.completion_cost(resp) or 0.0)
        except Exception:
            pass
        return resp.choices[0].message
