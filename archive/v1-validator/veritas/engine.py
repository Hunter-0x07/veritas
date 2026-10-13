"""引擎编排。

W1 用"回合制 + 并发 worker"近似事件驱动（确定性强、易验收）：
  planner 派意图 → N 个 worker 并发 drain（SKIP LOCKED 领取）→ 下一轮，
  直到无未测资产 + 无在途意图。纯事件驱动（debounce/LISTEN-NOTIFY）留 W2。
"""
from __future__ import annotations

import asyncio
import logging
import os
import pathlib
from urllib.parse import urlparse

from . import db, report
from .board import Board
from .config import Config
from .llm import LLMClient
from .oob import NoopOOB
from .planner import Planner
from .scope import Scope, ScopeError
from .seeds import default_seeds
from .tools import HttpTool, ReconTool, SkillTool
from .validators import build_registry
from .worker import Worker

_SKILLS_DIR = str(pathlib.Path(__file__).resolve().parent.parent / "skills")

log = logging.getLogger("veritas.engine")
SAFETY_ROUNDS = 50


def _normalize(target: str) -> str:
    return target if "://" in target else "http://" + target


async def run(cfg: Config, target: str, instruction: str | None = None):
    scope = Scope(cfg.scope)
    target = _normalize(target)

    # 安全底线：目标必须在授权范围内，否则一步都不走
    if not scope.allows(target):
        raise ScopeError(f"目标 {urlparse(target).hostname} 不在授权 scope，拒绝启动")
    if cfg.runtime.execution == "local":
        log.warning("⚠ local 执行模式：无沙箱，以当前用户权限运行。仅用于授权靶场。")

    pool = await db.connect(cfg.dsn)
    board = Board(pool)
    llm = None
    if cfg.llm.mode == "live":
        key = os.environ.get(cfg.llm.api_key_env) if cfg.llm.api_key_env else None
        llm = LLMClient(cfg.llm.model, cfg.llm.api_base, key,
                        cfg.llm.reasoning_effort, cfg.llm.extra_body)
    tools = [HttpTool(scope), ReconTool(scope), SkillTool(_SKILLS_DIR)]
    validators = build_registry()
    oob = NoopOOB()   # 真实 interactsh 接入后续替换

    task_id = await board.create_task(target)
    await board.add_node(task_id, "goal",
                         {"goal": f"对 {target} 做授权渗透并给出可信结论", "instruction": instruction})
    await board.add_asset(task_id, "endpoint", dedup_key=target, props={"url": target, "root": True})
    await board.emit_event(task_id, "task_started")

    # mock 模式预置候选漏洞（由 validator 真实裁决）；live 模式候选由 worker 探索产出
    if cfg.llm.mode != "live":
        for s in (cfg.seeds or default_seeds(target)):
            await board.add_finding(task_id, s)
    log.info("任务 %s 启动，目标 %s，模式 %s", task_id, target, cfg.llm.mode)

    planner = Planner(board, cfg, llm)
    workers = [Worker(f"w{i}", board, cfg, scope, tools, llm, validators, oob, instruction)
               for i in range(max(1, cfg.runtime.workers))]

    for rnd in range(1, SAFETY_ROUNDS + 1):
        decision = await planner.plan(task_id)
        if decision == "done":
            log.info("第 %d 轮：目标覆盖完成", rnd)
            break
        processed = await asyncio.gather(*[w.drain(task_id) for w in workers])
        log.info("第 %d 轮：%s 派意图，worker 处理 %d 条", rnd, decision, sum(processed))
    else:
        log.warning("达到安全轮次上限 %d，强制结束", SAFETY_ROUNDS)

    await board.set_task_state(task_id, "done")
    report_path = await report.generate(board, task_id, target)
    cost = llm.cost_usd if llm else 0.0
    await pool.close()
    return task_id, report_path, cost
