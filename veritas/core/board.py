"""Attack Graph 攻击图状态服务（= 黑板 / Stigmergy）。

所有 agent 只通过 board 协作。意图领取用 ARTEX 式条件 UPDATE CAS（取前沿候选逐条
UPDATE WHERE state='open'），无死锁、无长事务，适合多 worker 抢同一前沿。
"""
from __future__ import annotations

import uuid
from typing import Optional

import asyncpg

from .state import rank


class Board:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    # ---- task ----
    async def create_task(self, target: str, goal: str) -> str:
        tid = uuid.uuid4().hex[:12]
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO tasks(id,target,goal) VALUES($1,$2,$3)", tid, target, goal)
        return tid

    async def set_task_state(self, task_id: str, state: str) -> None:
        async with self.pool.acquire() as c:
            await c.execute("UPDATE tasks SET state=$2, updated_at=now() WHERE id=$1", task_id, state)

    # ---- footholds ----
    async def add_foothold(self, task_id: str, label: str, access_level: str,
                           location: Optional[str] = None, props: Optional[dict] = None,
                           verdict: str = "verified") -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                """INSERT INTO footholds(task_id,label,access_level,location,props,verdict)
                   VALUES($1,$2,$3,$4,$5,$6)
                   ON CONFLICT (task_id,label) DO UPDATE
                     SET access_level=EXCLUDED.access_level, verdict=EXCLUDED.verdict
                   RETURNING id""",
                task_id, label, access_level, location, props or {}, verdict)

    async def footholds(self, task_id: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch("SELECT * FROM footholds WHERE task_id=$1 ORDER BY id", task_id)

    async def max_access(self, task_id: str, verified_only: bool = True) -> str:
        """渗透进展度量。默认只认 verified 立足点（防幻觉：未过证据验证的声称不计入进展）。"""
        best = "external"
        for r in await self.footholds(task_id):
            if verified_only and r["verdict"] != "verified":
                continue
            if rank(r["access_level"]) > rank(best):
                best = r["access_level"]
        return best

    async def goal_reached(self, task_id: str, goal_level: str) -> bool:
        return rank(await self.max_access(task_id)) >= rank(goal_level)

    async def exec_traces(self, task_id: str) -> list[dict]:
        """真实 sandbox 执行记录（命令/退出码/输出），供 Verifier 证据溯源。"""
        rows = await self.activity_log(task_id)
        return [c for c in ((r["content"] or {}) for r in rows) if "exec" in c]

    # ---- assets ----
    async def add_asset(self, task_id: str, atype: str, dedup_key: str, *,
                        reachable_from: Optional[int] = None, props: Optional[dict] = None,
                        in_scope: bool = True) -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                """INSERT INTO assets(task_id,type,dedup_key,reachable_from,props,in_scope)
                   VALUES($1,$2,$3,$4,$5,$6)
                   ON CONFLICT (task_id,dedup_key) DO UPDATE SET type=EXCLUDED.type
                   RETURNING id""",
                task_id, atype, dedup_key, reachable_from, props or {}, in_scope)

    async def mark_asset_tested(self, asset_id: int) -> None:
        async with self.pool.acquire() as c:
            await c.execute("UPDATE assets SET tested=TRUE WHERE id=$1", asset_id)

    async def assets(self, task_id: str, *, atype: Optional[str] = None,
                     untested_only: bool = False) -> list[asyncpg.Record]:
        q = "SELECT * FROM assets WHERE task_id=$1 AND in_scope=TRUE"
        args = [task_id]
        if atype:
            q += " AND type=$2"; args.append(atype)
        if untested_only:
            q += " AND tested=FALSE"
        async with self.pool.acquire() as c:
            return await c.fetch(q + " ORDER BY id", *args)

    # ---- opportunities（CAS 领取）----
    async def add_opportunity(self, task_id: str, kind: str, *, from_foothold: Optional[int] = None,
                              target_asset: Optional[int] = None, payload: Optional[dict] = None) -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                """INSERT INTO opportunities(task_id,kind,from_foothold,target_asset,payload)
                   VALUES($1,$2,$3,$4,$5) RETURNING id""",
                task_id, kind, from_foothold, target_asset, payload or {})

    async def claim_opportunity(self, task_id: str, worker: str) -> Optional[asyncpg.Record]:
        """ARTEX 式 CAS：取前沿候选逐条 UPDATE WHERE state='open'，RETURNING 抢到即返回。"""
        async with self.pool.acquire() as c:
            cands = await c.fetch(
                """SELECT id FROM opportunities WHERE task_id=$1 AND state='open'
                   ORDER BY (payload->>'ev')::float DESC NULLS LAST, id LIMIT 20""", task_id)
            for r in cands:
                got = await c.fetchval(
                    """UPDATE opportunities SET state='claimed', claimed_by=$1, claimed_at=now()
                       WHERE id=$2 AND state='open' RETURNING id""", worker, r["id"])
                if got:
                    return await c.fetchrow("SELECT * FROM opportunities WHERE id=$1", got)
        return None

    async def set_opportunity_state(self, opp_id: int, state: str) -> None:
        async with self.pool.acquire() as c:
            await c.execute("UPDATE opportunities SET state=$2 WHERE id=$1", opp_id, state)

    async def count_pending_opportunities(self, task_id: str) -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                "SELECT count(*) FROM opportunities WHERE task_id=$1 AND state IN ('open','claimed')",
                task_id)

    async def opp_attempts(self, task_id: str, kind: str, from_foothold: Optional[int],
                           target_asset: Optional[int]) -> int:
        """同一前沿（kind + 起点 + 目标资产）已结束（done/failed）的尝试数，用于难点冗余重试封顶。"""
        async with self.pool.acquire() as c:
            return await c.fetchval(
                """SELECT count(*) FROM opportunities
                   WHERE task_id=$1 AND kind=$2 AND state IN ('done','failed')
                     AND from_foothold IS NOT DISTINCT FROM $3
                     AND target_asset  IS NOT DISTINCT FROM $4""",
                task_id, kind, from_foothold, target_asset)

    # ---- 战利品 / 漏洞 / 边 ----
    async def add_credential(self, task_id: str, kind: str, *, username: str = "", secret: str = "",
                             source: str = "", props: Optional[dict] = None,
                             verdict: str = "verified") -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                """INSERT INTO credentials(task_id,kind,username,secret,source,props,verdict)
                   VALUES($1,$2,$3,$4,$5,$6,$7)
                   ON CONFLICT (task_id,kind,username,secret) DO UPDATE
                     SET source=EXCLUDED.source, verdict=EXCLUDED.verdict
                   RETURNING id""",
                task_id, kind, username, secret, source, props or {}, verdict)

    async def credentials(self, task_id: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch("SELECT * FROM credentials WHERE task_id=$1 ORDER BY id", task_id)

    async def add_loot(self, task_id: str, kind: str, summary: str, props: Optional[dict] = None) -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                "INSERT INTO loot(task_id,kind,summary,props) VALUES($1,$2,$3,$4) RETURNING id",
                task_id, kind, summary, props or {})

    async def add_finding(self, task_id: str, ftype: str, *, foothold_id: Optional[int] = None,
                          asset_id: Optional[int] = None, severity: str = "",
                          evidence: Optional[dict] = None, reproduction: str = "") -> int:
        async with self.pool.acquire() as c:
            return await c.fetchval(
                """INSERT INTO findings(task_id,type,foothold_id,asset_id,severity,evidence,reproduction)
                   VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id""",
                task_id, ftype, foothold_id, asset_id, severity, evidence or {}, reproduction)

    async def add_edge(self, src: int, dst: int, rel: str, kind: str = "") -> None:
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO edges(src,dst,rel,kind) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
                            src, dst, rel, kind)

    # ---- activity / events ----
    async def write_activity(self, task_id: str, opp_id: Optional[int], worker: str,
                             step: int, content: dict) -> None:
        async with self.pool.acquire() as c:
            await c.execute(
                "INSERT INTO activity(task_id,opportunity_id,worker_id,step,content) VALUES($1,$2,$3,$4,$5)",
                task_id, opp_id, worker, step, content)

    async def emit_event(self, task_id: str, etype: str) -> None:
        async with self.pool.acquire() as c:
            await c.execute("INSERT INTO events(task_id,type) VALUES($1,$2)", task_id, etype)

    async def search_traces(self, task_id: str, query: str, *, exclude_worker: Optional[str] = None,
                            limit: int = 15) -> list[asyncpg.Record]:
        """跨 worker 过程检索（search_all_worker_traces）：舰队成员查别人跑过的命令/结果，
        避免重复侦察、复用凭据线索。默认排除自己。"""
        q = ("SELECT worker_id, step, content, created_at FROM activity "
             "WHERE task_id=$1 AND content::text ILIKE '%'||$2||'%'")
        args: list = [task_id, query]
        if exclude_worker:
            q += " AND worker_id IS DISTINCT FROM $3"
            args.append(exclude_worker)
        q += " ORDER BY id DESC LIMIT " + str(int(limit))
        async with self.pool.acquire() as c:
            return await c.fetch(q, *args)

    async def activity_log(self, task_id: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch("SELECT * FROM activity WHERE task_id=$1 ORDER BY id", task_id)

    async def foothold_edges(self, task_id: str) -> list[asyncpg.Record]:
        """血缘边（限本任务的立足点之间），供报告还原并行分支。"""
        async with self.pool.acquire() as c:
            return await c.fetch(
                """SELECT e.src, e.dst, e.rel FROM edges e
                   JOIN footholds fs ON fs.id=e.src AND fs.task_id=$1
                   JOIN footholds fd ON fd.id=e.dst AND fd.task_id=$1""", task_id)

    # ---- 读（report / kill chain）----
    async def loot(self, task_id: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch("SELECT * FROM loot WHERE task_id=$1 ORDER BY id", task_id)

    async def findings(self, task_id: str) -> list[asyncpg.Record]:
        async with self.pool.acquire() as c:
            return await c.fetch("SELECT * FROM findings WHERE task_id=$1 ORDER BY id", task_id)

    async def kill_chain(self, task_id: str) -> list[asyncpg.Record]:
        """按 exploits/pivots_to 边串出的立足点推进序列（按产生顺序近似）。"""
        return await self.footholds(task_id)
