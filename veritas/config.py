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
    sandbox_network: str = "host"   # M3 横向：连靶场 frontend 网，让 attacker 只能到 edge
    # web_solver 每个机会的 agentic loop 步数上限。冷图压缩把转录成本解耦后可放开，给未知深链更多探索余量。
    max_steps: int = 120
    # 冷图压缩（llm/compaction.py）阈值：转录超 compact_chars 字符(≈chars/4 tokens)就折叠；保留最近
    # compact_keep 个完整 round-trip 热前沿。效果优先→默认给宽松值（只在很长的 run 才触发；想 live 看
    # 触发可临时调小 compact_chars 强制触发）。
    compact_chars: int = 200000
    compact_keep: int = 8
    # 无进展熔断：web_solver loop 连续 no_progress_limit 步没拿到【新战果】(foothold/凭据/loot/finding)
    # 就提前收手——堵"够不到目标就满世界乱撞烧满预算"(实测对死 DC 绕 137 步/3.1M tokens)。效果优先→
    # 默认宽松(保护初期 recon：任一新战果都重置计数)；0=关闭。
    no_progress_limit: int = 30


@dataclass
class ProbeCfg:
    """verifier Stage 2 主动探针的 safe-probe 策略（见 core/prober.py）。

    第一性：真实目标是 HackerOne 这类【授权外部目标】，不能随便重活。默认 external（保守）——
    只放单次 nonce 回环这类低噪声探针；授权靶场显式声明 authorization=lab 才开重探针
    （重认证 / 重跑 DCSync）。"""
    enabled: bool = True
    authorization: str = "external"   # "lab"=授权靶场(各级可) | "external"=外部(仅低噪声)
    budget: int = 8                   # 本次 run 的主动探针执行预算（防对目标连续重活）
    llm_judge: bool = False           # 外部降级路径是否启用 LLM-judge 辅助评级（低信任档）
    oob_url: str | None = None        # OOB canary 监听器 base_url（SSRF/XXE 探针用；需引擎+目标都可达）


@dataclass
class Config:
    dsn: str
    target: str
    goal: str
    llm: LLMCfg
    runtime: RuntimeCfg
    scope: ScopeCfg
    probe: ProbeCfg

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
            probe=ProbeCfg(**{k: v for k, v in raw.get("probe", {}).items()
                              if k in ProbeCfg.__annotations__}),
        )
