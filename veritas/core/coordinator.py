"""Coordinator 协调者（持久、唯一规划者）。

读攻击图当前态势 → 按访问级别推进。M4 起每轮**分解并行**：同一访问阶段内按资产
fan-out 出多个前沿（多 web 资产 / 多内网主机），让 solver 舰队真正并行领取；跨阶段
仍串行（权限跃迁有依赖）。难点卡住时按 MAX_ATTEMPTS 冗余重试，超限放弃以解除阻塞。
权威状态始终在攻击图里。
"""
from __future__ import annotations

import logging

from .board import Board
from .state import rank, meets_goal

log = logging.getLogger("veritas.coordinator")

MAX_ATTEMPTS = 2  # 同一前沿的冗余重试上限（分解为主、冗余为辅）


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
        """返回 planned | waiting | done | exhausted。一轮可派出多个并行前沿。"""
        if await self.board.count_pending_opportunities(task_id) > 0:
            return "waiting"

        max_acc = await self.board.max_access(task_id)
        if meets_goal(max_acc, self.goal):
            await self.board.set_task_state(task_id, "reached")
            return "done"

        footholds = await self.board.footholds(task_id)
        top = self._top(footholds)
        creds = await self.board.credentials(task_id)
        all_webapps = await self.board.assets(task_id, atype="webapp")
        all_hosts = await self.board.assets(task_id, atype="host")
        webapps = [w for w in all_webapps if not w["tested"]]
        hosts = [h for h in all_hosts if not h["tested"]]

        # 候选前沿：(kind, from_foothold, target_asset, payload)
        batch: list[tuple] = []
        if max_acc == "external" and webapps:
            for w in webapps:  # 多 web 资产 → 并行初始访问
                batch.append(("initial_access", top["id"], w["id"],
                              {"ev": 10, "location": (w["props"] or {}).get("url", w["dedup_key"])}))
        elif rank(max_acc) == rank("web_user"):
            batch.append(("web_exploit", top["id"], None,
                          {"ev": 9, "location": top["location"]}))
        elif rank("web_admin") <= rank(max_acc) < rank("shell") and not all_hosts:
            batch.append(("internal_recon", top["id"], None, {"ev": 8}))
        elif hosts and creds:
            for h in hosts:  # 多内网主机 → 并行横向
                batch.append(("lateral_move", top["id"], h["id"],
                              {"ev": 9, "host": h["dedup_key"]}))

        # 冗余重试封顶：超过 MAX_ATTEMPTS 仍未成功的资产标记 tested（放弃），避免卡在前沿
        emitted = 0
        for kind, ff, ta, payload in batch:
            attempts = await self.board.opp_attempts(task_id, kind, ff, ta)
            if attempts >= MAX_ATTEMPTS:
                if ta is not None:
                    await self.board.mark_asset_tested(ta)
                log.info("前沿 %s(asset=%s) 已重试 %d 次仍未成功，放弃", kind, ta, attempts)
                continue
            payload = {**payload, "attempt": attempts + 1, "max_attempts": MAX_ATTEMPTS}
            await self.board.add_opportunity(task_id, kind, from_foothold=ff,
                                             target_asset=ta, payload=payload)
            emitted += 1

        if emitted == 0:
            await self.board.set_task_state(task_id, "exhausted")
            return "exhausted"

        await self.board.emit_event(task_id, "opportunity_created")
        log.info("规划 %d 个并行前沿（max_access=%s）", emitted, max_acc)
        return "planned"
