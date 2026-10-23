"""推进引擎。

回合制舰队：Coordinator 分解出多个并行前沿 → N 个 solver 并发 drain（CAS 领取）→ 下一轮，
直到达成 goal 或前沿耗尽。M4 起 live 模式下**每个 solver 独享一个 Kali 沙箱**（fresh
session，互不踩），舰队间只通过攻击图 + search_worker_traces 协作。
纯事件驱动（debounce / LISTEN-NOTIFY）留 M5。
"""
from __future__ import annotations

import asyncio
import logging

from .. import db
from ..config import Config
from ..executors import build_registry
from ..llm import LLMClient
from ..report import killchain
from ..runtime import Sandbox
from .board import Board
from .coordinator import Coordinator
from .observer import Observer
from .solver import Solver
from .verifier import Verifier

log = logging.getLogger("veritas.engine")


async def run(cfg: Config, target: str | None = None, goal: str | None = None):
    target = target or cfg.target
    goal = goal or cfg.goal
    if not target:
        raise ValueError("未指定目标（--target 或 dispatch.yaml 的 target）")

    pool = await db.connect(cfg.dsn)
    board = Board(pool)

    task_id = await board.create_task(target, goal)
    ext = await board.add_foothold(task_id, "external", "external", target)  # 初始立足点
    await board.add_asset(task_id, "webapp", target, props={"url": target})
    await board.emit_event(task_id, "task_started")
    log.info("任务 %s 启动 · 目标 %s · goal=%s · 模式 %s", task_id, target, goal, cfg.llm.mode)

    nworkers = max(1, cfg.runtime.workers)
    llm = None
    sandboxes: list[Sandbox] = []
    coord = Coordinator(board, goal)
    verifier = Verifier(cfg.llm.mode)      # 证据确定性验证层（防幻觉）
    observer = Observer(board, goal)       # 旁路监督（失速/鬼打墙/早停·误报）

    if cfg.llm.mode == "live":
        # 每个 solver 独享一个 Kali 沙箱（舰队并行、互不踩），舰队间只经攻击图/trace 协作。
        # 沙箱按需启动（solver 真正领到活才起），单目标跑不白占 N 个容器。
        llm = LLMClient(cfg.llm)
        sandboxes = [Sandbox(f"veritas-{task_id[:8]}-s{i}", network=cfg.runtime.sandbox_network)
                     for i in range(nworkers)]
        # safe-probe 策略（Stage 2 主动探针）：executor 持沙箱在 verifier 判定前主动证成/证伪。
        # OOB canary（Stage 3 Cut 2b）：配了 probe.oob_url 用 HttpOOB，否则 NoopOOB（SSRF/XXE 判 inconclusive）。
        from ..runtime.oob import HttpOOB, NoopOOB
        from ..safety.autonomy import AutonomyPolicy
        oob = HttpOOB(cfg.probe.oob_url) if getattr(cfg.probe, "oob_url", None) else NoopOOB()
        # 安全闸：scope 授权边界 + 分级自主/审批门（approval 模式对破坏性/高噪声动作 fail-closed）。
        autonomy = AutonomyPolicy.from_cfg(getattr(cfg, "autonomy", None), cfg.probe)
        solvers = [Solver(f"s{i}", board,
                          build_registry("live", llm, sandboxes[i], scope=cfg.scope,
                                         probe_policy=cfg.probe, oob=oob, runtime=cfg.runtime,
                                         autonomy=autonomy), verifier)
                   for i in range(nworkers)]
        log.info("safe-probe 策略：authorization=%s · budget=%d · llm_judge=%s · oob=%s",
                 cfg.probe.authorization, cfg.probe.budget, cfg.probe.llm_judge,
                 "on" if getattr(oob, "available", False) else "off")
        _scope_on = bool(cfg.scope.domains or cfg.scope.cidrs)
        log.info("安全闸：scope=%s（域 %d / 网段 %d）· autonomy mode=%s on_gated=%s",
                 "on" if _scope_on else "off（未配置→不强制）",
                 len(cfg.scope.domains), len(cfg.scope.cidrs), autonomy.mode, autonomy.on_gated)
    else:
        solvers = [Solver(f"s{i}", board, build_registry("mock"), verifier)
                   for i in range(nworkers)]

    decision = "init"
    try:
        for rnd in range(1, cfg.runtime.max_rounds + 1):
            decision = await coord.plan(task_id)
            if decision in ("done", "exhausted"):
                log.info("第 %d 轮：%s", rnd, "目标达成 ✓" if decision == "done" else "前沿耗尽")
                break
            processed = await asyncio.gather(*[s.drain(task_id) for s in solvers])
            busy = sum(1 for p in processed if p)
            log.info("第 %d 轮：%s，舰队 %d/%d 并行就位，处理 %d 条",
                     rnd, decision, busy, nworkers, sum(processed))
            await observer.observe(task_id, rnd, decision)
        else:
            decision = "maxrounds"
            log.warning("达到轮次上限 %d，强制结束", cfg.runtime.max_rounds)
        await observer.conclude(task_id, decision)
    finally:
        if sandboxes:
            await asyncio.gather(*[sb.stop() for sb in sandboxes], return_exceptions=True)

    report_path, reached, max_acc = await killchain.generate(board, task_id, target, goal,
                                                             mode=cfg.llm.mode)
    if llm is not None:
        log.info("LLM 用量: in=%d out=%d tokens · 估算成本 $%.4f（glm 实际费用以智谱后台为准）",
                 llm.tokens_in, llm.tokens_out, llm.cost_usd)
    await pool.close()
    return task_id, report_path, reached, max_acc
