"""Observer 旁路监督（BreachWeave 式）。

不参与推进，只在旁边盯着整条 run 防跑偏：失速（连续轮次无 verified 跃迁）、鬼打墙
（同一 worker 重复同一失败命令）、早停 / 误报（前沿耗尽却仍有未测资产，或有人声称达到
goal 却没过证据验证）。发现写进 activity（worker=observer），报告据此给结论可信度。
确定性实现（不烧 token）；LLM 终局复核留后续。
"""
from __future__ import annotations

import logging

from .board import Board
from .state import meets_goal

log = logging.getLogger("veritas.observer")


class Observer:
    STALL_ROUNDS = 3   # 连续多少轮 verified 访问无跃迁判失速
    RUT_N = 3          # 同一 (worker,命令) 失败多少次判鬼打墙

    def __init__(self, board: Board, goal: str):
        self.board = board
        self.goal = goal
        self._hist: list[str] = []
        self._seen: set[str] = set()

    async def observe(self, task_id: str, rnd: int, decision: str) -> None:
        acc = await self.board.max_access(task_id, verified_only=True)
        self._hist.append(acc)
        if (len(self._hist) >= self.STALL_ROUNDS
                and len(set(self._hist[-self.STALL_ROUNDS:])) == 1
                and not meets_goal(acc, self.goal)):
            await self._flag(task_id, "stall",
                             f"连续 {self.STALL_ROUNDS} 轮 verified 访问停在 `{acc}`，疑似失速")
        await self._detect_ruts(task_id)

    async def conclude(self, task_id: str, decision: str) -> None:
        footholds = await self.board.footholds(task_id)
        bad = [f for f in footholds
               if f["verdict"] != "verified" and meets_goal(f["access_level"], self.goal)]
        if bad:
            labels = ", ".join(f["label"] for f in bad)
            await self._flag(task_id, "false_positive",
                             f"有 solver 声称达到 goal(`{self.goal}`) 但未过证据验证："
                             f"{labels} —— 已判未达成（防误报）")
        if decision == "exhausted":
            untested = await self.board.assets(task_id, untested_only=True)
            if untested:
                keys = ", ".join(a["dedup_key"] for a in untested[:5])
                await self._flag(task_id, "early_stop",
                                 f"前沿耗尽但仍有 {len(untested)} 个资产未攻破（{keys}…），可能早停")

    async def _detect_ruts(self, task_id: str) -> None:
        counts: dict[tuple, int] = {}
        for r in await self.board.activity_log(task_id):
            c = r["content"] or {}
            if "exec" in c and c.get("rc") not in (0, None):
                key = (r["worker_id"], c["exec"])
                counts[key] = counts.get(key, 0) + 1
        for (worker, cmd), n in counts.items():
            if n >= self.RUT_N:
                await self._flag(task_id, f"rut:{worker}:{cmd[:60]}",
                                 f"[{worker}] 重复失败命令 {n} 次：`{cmd[:120]}`（鬼打墙，建议换招）")

    async def _flag(self, task_id: str, key: str, detail: str) -> None:
        if key in self._seen:
            return
        self._seen.add(key)
        log.warning("Observer · %s", detail)
        await self.board.write_activity(task_id, None, "observer", 0,
                                        {"observer": key.split(":")[0], "detail": detail})
