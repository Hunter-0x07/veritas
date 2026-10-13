"""推进引擎。

M0 用回合制：Coordinator 派机会 → N 个 solver 并发 drain（CAS 领取）→ 下一轮，
直到达成 goal 或前沿耗尽。纯事件驱动（debounce / LISTEN-NOTIFY）留 M4。
"""
from __future__ import annotations

import asyncio
import logging

from .. import db
from ..config import Config
from ..executors import build_registry
from ..report import killchain
from .board import Board
from .coordinator import Coordinator
from .solver import Solver

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

    coord = Coordinator(board, goal)
    executors = build_registry(cfg.llm.mode)
    solvers = [Solver(f"s{i}", board, executors) for i in range(max(1, cfg.runtime.workers))]

    for rnd in range(1, cfg.runtime.max_rounds + 1):
        decision = await coord.plan(task_id)
        if decision in ("done", "exhausted"):
            log.info("第 %d 轮：%s", rnd, "目标达成 ✓" if decision == "done" else "前沿耗尽")
            break
        processed = await asyncio.gather(*[s.drain(task_id) for s in solvers])
        log.info("第 %d 轮：%s，solver 处理 %d 条", rnd, decision, sum(processed))
    else:
        log.warning("达到轮次上限 %d，强制结束", cfg.runtime.max_rounds)

    report_path, reached, max_acc = await killchain.generate(board, task_id, target, goal)
    await pool.close()
    return task_id, report_path, reached, max_acc
