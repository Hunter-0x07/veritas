"""L1 规划层 —— 唯一意图生成者。

读全局态势（覆盖度/事实/未测资产），为未测资产派探索意图；无未测资产且
无在途意图时，判定任务完成。mock 模式用规则；live 模式用 LLM，失败回退规则。
"""
from __future__ import annotations

import json
import logging

from .board import Board
from .config import Config
from .llm import LLMClient

log = logging.getLogger("veritas.planner")


class Planner:
    def __init__(self, board: Board, cfg: Config, llm: LLMClient | None):
        self.board = board
        self.cfg = cfg
        self.llm = llm

    async def _goal_id(self, task_id: str) -> int | None:
        goals = await self.board.nodes_by_kind(task_id, "goal")
        return goals[0]["id"] if goals else None

    async def plan(self, task_id: str) -> str:
        """返回 'planned' | 'waiting' | 'done'。"""
        pending = await self.board.count_pending_intents(task_id)
        if pending > 0:
            return "waiting"                       # 还有意图没消化，先别再派

        goal_id = await self._goal_id(task_id)

        # 1) 优先裁决候选 finding —— 验证是确定性的，不经 LLM
        cands = await self.board.pending_candidate_findings(task_id)
        if cands:
            for c in cands:
                iid = await self.board.add_node(task_id, "intent", {
                    "action": "validate", "finding_id": c["id"],
                    "type": c["payload"].get("type"), "ev": 10.0,
                })
                if goal_id:
                    await self.board.add_edge(goal_id, iid, "spawns")
                await self.board.add_edge(iid, c["id"], "proves")
            await self.board.emit_event(task_id, "validate_created")
            return "planned"

        # 2) 再探测未测资产
        untested = await self.board.untested_in_scope_assets(task_id)
        if not untested:
            await self.board.set_task_state(task_id, "done")
            return "done"

        for t in await self._decide(task_id, untested):
            iid = await self.board.add_node(task_id, "intent", {
                "action": "probe", "target_url": t["target_url"],
                "asset_id": t["asset_id"], "ev": t.get("ev", 0.0),
            })
            if goal_id:
                await self.board.add_edge(goal_id, iid, "spawns")
            await self.board.add_anchor(iid, t["asset_id"])
        await self.board.emit_event(task_id, "intents_created")
        return "planned"

    async def _decide(self, task_id: str, untested) -> list[dict]:
        rule = [{"action": "probe", "target_url": (a["props"] or {}).get("url", a["dedup_key"]),
                 "asset_id": a["id"], "ev": a["score"]} for a in untested]
        if self.cfg.llm.mode != "live" or not self.llm:
            return rule
        # live：让 LLM 基于态势挑选/排序方向（W1 基础版，出错回退规则）
        try:
            overview = await self.board.overview(task_id)
            menu = [{"asset_id": a["id"], "url": (a["props"] or {}).get("url", a["dedup_key"])}
                    for a in untested]
            msg = [
                {"role": "system", "content": "你是渗透规划者。只输出 JSON 数组，每项 "
                 '{"action","target_url","asset_id"}，为未测资产规划下一步探索方向。'},
                {"role": "user", "content": f"态势:\n{overview}\n\n未测资产:\n{json.dumps(menu, ensure_ascii=False)}"},
            ]
            out = await self.llm.chat(msg)
            data = json.loads((out.content or "[]").strip().removeprefix("```json").removeprefix("```").removesuffix("```"))
            picks = [d for d in data if "asset_id" in d and "target_url" in d]
            return picks or rule
        except Exception as e:  # noqa: BLE001
            log.warning("planner live 回退规则: %s", e)
            return rule
