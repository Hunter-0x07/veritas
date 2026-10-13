"""配置加载：dispatch.yaml → 强类型对象。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml


@dataclass
class ScopeCfg:
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)


@dataclass
class LLMCfg:
    mode: str = "mock"          # mock | live
    model: str = "anthropic/claude-sonnet-4-6"
    api_base: str | None = None        # OpenAI 兼容端点（GLM/Qwen 等）需要
    api_key_env: str | None = None     # 从哪个环境变量读 key（默认走 litellm 约定）
    reasoning_effort: str | None = None  # 顶层传（litellm 对未知推理模型可能 drop；GLM 建议走 extra_body）
    extra_body: dict | None = None       # 透传 provider 特定参数，最稳；GLM-5.3: {reasoning_effort: low/high/max}


@dataclass
class RuntimeCfg:
    execution: str = "local"
    workers: int = 2
    debounce_seconds: float = 2.0
    max_steps: int = 40
    budget_usd: float = 2.0


@dataclass
class Config:
    dsn: str
    llm: LLMCfg
    runtime: RuntimeCfg
    scope: ScopeCfg
    seeds: list | None = None        # mock 模式的候选漏洞种子（None → 内置 Juice Shop 默认）

    @staticmethod
    def load(path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        db = raw.get("database", {})
        dsn = os.environ.get("VERITAS_DSN") or db.get("dsn")
        if not dsn:
            raise ValueError("database.dsn 未配置（或设置 VERITAS_DSN）")
        return Config(
            dsn=dsn,
            llm=LLMCfg(**{k: v for k, v in raw.get("llm", {}).items()
                          if k in {"mode", "model", "api_base", "api_key_env",
                                   "reasoning_effort", "extra_body"}}),
            runtime=RuntimeCfg(**{k: v for k, v in raw.get("runtime", {}).items()
                                  if k in RuntimeCfg.__annotations__}),
            scope=ScopeCfg(**{k: v for k, v in raw.get("scope", {}).items() if k in {"domains", "cidrs"}}),
            seeds=raw.get("seeds"),
        )
