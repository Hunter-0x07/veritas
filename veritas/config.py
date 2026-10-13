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
    model: str = "openai/glm-5.3"
    api_base: str | None = None
    api_key_env: str | None = None
    reasoning_effort: str | None = None
    extra_body: dict | None = None


@dataclass
class RuntimeCfg:
    execution: str = "local"
    workers: int = 2
    max_rounds: int = 30
    budget_usd: float = 5.0


@dataclass
class Config:
    dsn: str
    target: str
    goal: str
    llm: LLMCfg
    runtime: RuntimeCfg
    scope: ScopeCfg

    @staticmethod
    def load(path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        dsn = os.environ.get("VERITAS_DSN") or raw.get("database", {}).get("dsn")
        if not dsn:
            raise ValueError("database.dsn 未配置（或设置 VERITAS_DSN）")
        return Config(
            dsn=dsn,
            target=raw.get("target", ""),
            goal=raw.get("goal", "shell"),
            llm=LLMCfg(**{k: v for k, v in raw.get("llm", {}).items()
                          if k in {"mode", "model", "api_base", "api_key_env",
                                   "reasoning_effort", "extra_body"}}),
            runtime=RuntimeCfg(**{k: v for k, v in raw.get("runtime", {}).items()
                                  if k in RuntimeCfg.__annotations__}),
            scope=ScopeCfg(**{k: v for k, v in raw.get("scope", {}).items() if k in {"domains", "cidrs"}}),
        )
