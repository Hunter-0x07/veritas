"""Solver（舰队成员）：CAS 领取攻击机会 → 交执行器落地 → 把跃迁写回攻击图。

M0 的决策在 MockExecutor 里脚本化；M1+ solver 自身用 LLM 决策，再调执行器。
"""
from __future__ import annotations

import logging

from ..executors import Executor
from .board import Board

log = logging.getLogger("veritas.solver")


class Solver:
    def __init__(self, wid: str, board: Board, executors: dict[str, Executor]):
        self.wid = wid
        self.board = board
        self.executors = executors

    async def drain(self, task_id: str) -> int:
        """把当前可领的机会都做掉，返回处理条数。"""
        n = 0
        while True:
            opp = await self.board.claim_opportunity(task_id, self.wid)
            if opp is None:
                return n
            await self._run(task_id, opp)
            n += 1

    async def _run(self, task_id: str, opp) -> None:
        ex = self.executors.get(opp["kind"])
        if ex is None:
            await self.board.set_opportunity_state(opp["id"], "failed")
            return
        try:
            res = await ex.execute(opp, self.board, task_id)
        except Exception as e:  # noqa: BLE001
            log.warning("solver %s 执行异常: %s", self.wid, e)
            await self.board.write_activity(task_id, opp["id"], self.wid, 0, {"error": str(e)})
            await self.board.set_opportunity_state(opp["id"], "failed")
            return

        if res.success:
            await self._apply(task_id, opp, res.transition)
        await self.board.set_opportunity_state(opp["id"], "done" if res.success else "failed")
        if opp["target_asset"]:
            await self.board.mark_asset_tested(opp["target_asset"])
        await self.board.write_activity(task_id, opp["id"], self.wid, 1,
                                        {"kind": opp["kind"], "ok": res.success, "summary": res.summary})
        await self.board.emit_event(task_id, "transition")
        log.info("solver %s · %-15s → %s", self.wid, opp["kind"], res.summary)

    async def _apply(self, task_id: str, opp, tr) -> None:
        """把跃迁落进攻击图，并连 kill-chain 血缘边。"""
        src = opp["from_foothold"]
        for f in tr.footholds:
            fid = await self.board.add_foothold(task_id, f["label"], f["access_level"],
                                                f.get("location"), f.get("props"))
            if src:
                rel = "pivots_to" if f["access_level"] == "shell" else "exploits"
                await self.board.add_edge(src, fid, rel, "foothold")
        for cr in tr.credentials:
            await self.board.add_credential(task_id, cr["kind"], username=cr.get("username", ""),
                                             secret=cr.get("secret", ""), source=cr.get("source", ""))
        for lo in tr.loot:
            await self.board.add_loot(task_id, lo["kind"], lo["summary"], lo.get("props"))
        for a in tr.assets:
            await self.board.add_asset(task_id, a["type"], a["dedup_key"],
                                       reachable_from=a.get("reachable_from"),
                                       props=a.get("props"), in_scope=a.get("in_scope", True))
        for fd in tr.findings:
            await self.board.add_finding(task_id, fd["type"], foothold_id=src,
                                         severity=fd.get("severity", ""),
                                         reproduction=fd.get("reproduction", ""))
