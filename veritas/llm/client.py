"""LLM 客户端：live 模式走 LiteLLM（多 provider），带成本累计。

provider 预设（GLM/DeepSeek/OpenAI/Anthropic）由 llm/providers.py 补全 model/端点/key 环境变量，
显式 cfg 字段可覆盖。LiteLLM 统一各家 tool-use 与响应格式，故切 provider 时 executor 零改动。
GLM-5.3 经 OpenAI 兼容端点。mock 模式不调本模块。
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from ..config import LLMCfg
from . import providers

log = logging.getLogger("veritas.llm")


class LLMClient:
    def __init__(self, cfg: LLMCfg):
        eff = providers.resolve(cfg.provider, cfg.model, cfg.api_base, cfg.api_key_env)
        self.provider = eff["provider"]
        self.model = eff["model"]
        self.api_base = eff["api_base"]
        self.api_key_env = eff["api_key_env"]
        self.api_key = os.environ.get(eff["api_key_env"]) if eff["api_key_env"] else None
        self.reasoning_effort = cfg.reasoning_effort
        self.extra_body = cfg.extra_body
        self.cost_usd = 0.0
        self.tokens_in = 0
        self.tokens_out = 0
        if not self.model:
            raise ValueError(f"未解析出 LLM model：provider={cfg.provider!r} 未知且未显式设 llm.model")
        if self.api_key_env and not self.api_key:
            log.warning("LLM provider=%s 的 key 环境变量 %s 未设置——live 调用会失败",
                        self.provider, self.api_key_env)
        log.info("LLM provider=%s · model=%s%s", self.provider, self.model,
                 f" · api_base={self.api_base}" if self.api_base else "")

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
