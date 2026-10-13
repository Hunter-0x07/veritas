"""Coordinator 协调者（持久、唯一规划者）。

读攻击图当前态势 → 按访问级别推进，派下一个攻击机会。M0 用规则驱动串行 kill chain；
M1+ 换成 LLM 规划 + 跨唤醒共享 todolist（权威状态始终在攻击图里）。
"""
from __future__ import annotations

import logging

from .board import Board
from .state import meets_goal, rank

log = logging.getLogger("veritas.coordinator")


class Coordinator:
    def __init__(self, board: Board, goal: str):
        self.board = board
        self.goal = goal

    @staticmethod
    def _top(footholds) -> dict | None:
        best = None
        for f in footholds:
            if best is None or rank(f["access_level"]) > rank(best["access_level"]):
                best = f
        return dict(best) if best is not None else None

    async def plan(self, task_id: str) -> str:
        """返回 planned | waiting | done | exhausted。"""
        if await self.board.count_pending_opportunities(task_id) > 0:
            return "waiting"

        max_acc = await self.board.max_access(task_id)
        if meets_goal(max_acc, self.goal):
            await self.board.set_task_state(task_id, "reached")
            return "done"

        footholds = await self.board.footholds(task_id)
        top = self._top(footholds)
        creds = await self.board.credentials(task_id)
        webapps = await self.board.assets(task_id, atype="webapp", untested_only=True)
        hosts = await self.board.assets(task_id, atype="host", untested_only=True)

        if max_acc == "external" and webapps:
            w = webapps[0]
            await self.board.add_opportunity(task_id, "initial_access", from_foothold=top["id"],
                target_asset=w["id"],
                payload={"ev": 10, "location": (w["props"] or {}).get("url", w["dedup_key"])})
        elif max_acc == "web_user":
            await self.board.add_opportunity(task_id, "web_exploit", from_foothold=top["id"],
                payload={"ev": 9, "location": top["location"]})
        elif max_acc == "web_admin" and not hosts:
            await self.board.add_opportunity(task_id, "internal_recon", from_foothold=top["id"],
                payload={"ev": 8})
        elif hosts and creds:
            h = hosts[0]
            await self.board.add_opportunity(task_id, "lateral_move", from_foothold=top["id"],
                target_asset=h["id"], payload={"ev": 9, "host": h["dedup_key"]})
        else:
            await self.board.set_task_state(task_id, "exhausted")
            return "exhausted"

        await self.board.emit_event(task_id, "opportunity_created")
        return "planned"
