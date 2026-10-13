"""Board —— 双图读写 API（探索血缘图 + 资产真值图）。

所有 agent 只通过 Board 协作（Stigmergy，间接协作）。意图领取用
SELECT ... FOR UPDATE SKIP LOCKED，天然防重复领取。
"""
from __future__ import annotations

import uuid
from typing import Optional

import asyncpg


class Board:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    # ---- task ----
    async def create_task(self, target: str) -> str:
        tid = uuid.uuid4().hex[:12]
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO tasks(id, target) VALUES($1,$2)", tid, target)
        return tid

    async def set_task_state(self, task_id: str, state: str) -> None:
        async with self.pool.acquire() as c:
            await c.execute("UPDATE tasks SET state=$2, updated_at=now() WHERE id=$1", task_id, state)

    async def task_state(self, task_id: str) -> str:
        async with self.pool.acquire() as c:
            return await c.fetchval("SELECT state FROM tasks WHERE id=$1", task_id)

    # ---- assets ----
    async def add_asset(self, task_id: str, atype: str, dedup_key: str, *,
                        parent_id: Optional[int] = None, props: Optional[dict] = None,
                        in_scope: bool = True) -> int:
        async with self.pool.acquire() as c:
            row = await c.fetchrow(
                """INSERT INTO assets(task_id,type,dedup_key,parent_id,props,in_scope)
                   VALUES($1,$2,$3,$4,$5,$6)
                   ON CONFLICT (task_id,dedup_key) DO UPDATE SET task_id=EXCLUDED.task_id
                   RETURNING id""",
                task_id, atype, dedup_key, parent_id, props or {}, in_scope)
            return row["id"]

    async def mark_asset_tested(self, asset_id: int) -> None:
        async with self.pool.acquire() as c:
            await c.execute("UPDATE assets SET tested=TRUE WHERE id=$1", asset_id)

    async def get_asset(self, asset_id: int) -> Optional[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetchrow("SELECT * FROM assets WHERE id=$1", asset_id)

    async def untested_in_scope_assets(self, task_id: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch(
                "SELECT * FROM assets WHERE task_id=$1 AND tested=FALSE AND in_scope=TRUE ORDER BY score DESC, id",
                task_id)

    async def coverage(self, task_id: str) -> tuple[int, int]:
        """(已测, 范围内总数)。"""
        async with self.pool.acquire() as c:
            total = await c.fetchval("SELECT count(*) FROM assets WHERE task_id=$1 AND in_scope=TRUE", task_id)
            done = await c.fetchval(
                "SELECT count(*) FROM assets WHERE task_id=$1 AND in_scope=TRUE AND tested=TRUE", task_id)
            return done, total

    # ---- nodes / edges ----
    async def add_node(self, task_id: str, kind: str, payload: dict, *,
                       state: str = "open", provenance: Optional[dict] = None) -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                """INSERT INTO nodes(task_id,kind,state,payload,provenance)
                   VALUES($1,$2,$3,$4,$5) RETURNING id""",
                task_id, kind, state, payload, provenance or {})

    async def add_edge(self, src: int, dst: int, rel: str) -> None:
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO edges(src,dst,rel) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                            src, dst, rel)

    async def add_anchor(self, node_id: int, asset_id: int) -> None:
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
                            node_id, asset_id)

    # ---- intent lifecycle ----
    async def claim_intent(self, task_id: str, worker_id: str) -> Optional[asyncpg.Record]:
        """原子领取一条 open 意图（SKIP LOCKED 防竞态）。"""
        async with self.pool.acquire() as c:
            return await c.fetchrow(
                """UPDATE nodes SET state='claimed', claimed_by=$1, claimed_at=now()
                   WHERE id = (
                     SELECT id FROM nodes
                     WHERE task_id=$2 AND kind='intent' AND state='open'
                     ORDER BY (payload->>'ev')::float DESC NULLS LAST, id
                     FOR UPDATE SKIP LOCKED LIMIT 1
                   ) RETURNING *""",
                worker_id, task_id)

    async def set_intent_done(self, intent_id: int) -> None:
        async with self.pool.acquire() as c:
            await c.execute("UPDATE nodes SET state='done' WHERE id=$1", intent_id)

    async def count_pending_intents(self, task_id: str) -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                "SELECT count(*) FROM nodes WHERE task_id=$1 AND kind='intent' AND state IN ('open','claimed')",
                task_id)

    # ---- findings（候选 → 三态裁决）----
    @staticmethod
    def _finding_key(p: dict) -> tuple:
        return (p.get("type"), (p.get("url") or "").split("?", 1)[0], p.get("param") or "")

    async def add_finding(self, task_id: str, payload: dict) -> int:
        """登记候选 finding；同 (type, url去query, param) 已存在则复用，避免重复计数。"""
        key = self._finding_key(payload)
        async with self.pool.acquire() as c:
            rows = await c.fetch(
                "SELECT id, payload FROM nodes WHERE task_id=$1 AND kind='finding'", task_id)
        for r in rows:
            if self._finding_key(r["payload"] or {}) == key:
                return r["id"]
        return await self.add_node(task_id, "finding", payload, state="candidate")

    async def pending_candidate_findings(self, task_id: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch(
                "SELECT * FROM nodes WHERE task_id=$1 AND kind='finding' AND state='candidate' ORDER BY id",
                task_id)

    async def get_node(self, node_id: int) -> Optional[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetchrow("SELECT * FROM nodes WHERE id=$1", node_id)

    async def set_finding_verdict(self, fid: int, verdict: str, evidence: dict, reproduction: str) -> None:
        node = await self.get_node(fid)
        payload = dict(node["payload"]) if node else {}
        payload.update({"evidence": evidence, "reproduction": reproduction})
        async with self.pool.acquire() as c:
            await c.execute("UPDATE nodes SET state=$2, payload=$3 WHERE id=$1", fid, verdict, payload)

    # ---- activity / events ----
    async def write_activity(self, task_id: str, intent_id: Optional[int], worker_id: str,
                             step: int, content: dict) -> None:
        async with self.pool.acquire() as c:
            await c.execute(
                "INSERT INTO activity(task_id,intent_id,worker_id,step,content) VALUES($1,$2,$3,$4,$5)",
                task_id, intent_id, worker_id, step, content)

    async def emit_event(self, task_id: str, etype: str) -> None:
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO events(task_id,type) VALUES($1,$2)", task_id, etype)

    # ---- read for planner / report ----
    async def nodes_by_kind(self, task_id: str, kind: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch("SELECT * FROM nodes WHERE task_id=$1 AND kind=$2 ORDER BY id", task_id, kind)

    async def overview(self, task_id: str) -> str:
        """给 planner 的态势快照（纯文本，便于喂 LLM）。"""
        done, total = await self.coverage(task_id)
        async with self.pool.acquire() as c:
            facts = await c.fetch(
                "SELECT payload FROM nodes WHERE task_id=$1 AND kind='fact' ORDER BY id DESC LIMIT 20", task_id)
            findings = await c.fetch(
                "SELECT state,payload FROM nodes WHERE task_id=$1 AND kind='finding' ORDER BY id DESC", task_id)
            untested = await c.fetch(
                "SELECT type,dedup_key FROM assets WHERE task_id=$1 AND tested=FALSE AND in_scope=TRUE", task_id)
        lines = [f"覆盖度: {done}/{total} 资产已测",
                 f"未测资产: {[dict(r) for r in untested]}",
                 f"近期事实: {[r['payload'] for r in facts]}",
                 f"漏洞: {[(r['state'], r['payload']) for r in findings]}"]
        return "\n".join(lines)
