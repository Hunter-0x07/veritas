"""跨 run 策略记忆 · 真 Postgres 集成测试（临时库，不碰主库；无 DB 优雅 SKIP）。
验 board.add_strategy / search_strategies 的 DB 层：TEXT[] 标签重叠、JSONB steps、ILIKE、
exclude_task、relevance 排序、脱敏持久化。`.venv/bin/python tests/memory/test_memory_db.py`
"""
import sys, os, asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

ADMIN = os.environ.get("VERITAS_DSN", "postgresql://veritas:veritas@127.0.0.1:5432/veritas")
TEMP = ADMIN.rsplit("/", 1)[0] + "/veritas_memtest"

try:
    import asyncpg  # noqa: F401
except Exception:  # noqa: BLE001
    print("SKIP: asyncpg 不可用"); sys.exit(0)

_fail = 0
def check(name, got, want):
    global _fail
    if got != want:
        _fail += 1
        print(f"  ✗ {name}: got={got!r} want={want!r}")
    else:
        print(f"  ✓ {name}")


async def main():
    global _fail
    import asyncpg
    from veritas import db
    from veritas.core.board import Board
    from veritas.core import memory as m

    try:
        admin = await asyncio.wait_for(asyncpg.connect(ADMIN), timeout=5)
    except Exception as e:  # noqa: BLE001
        print(f"SKIP: 连不上 Postgres（{type(e).__name__}）——集成测试需本地 veritas DB 在 {ADMIN}")
        return 0
    await admin.execute("DROP DATABASE IF EXISTS veritas_memtest")
    await admin.execute("CREATE DATABASE veritas_memtest")
    await admin.close()

    pool = await db.connect(TEMP)      # 应用 schema.sql（含 strategies 表 + GIN 索引）
    board = Board(pool)
    try:
        # 蒸馏一条带【假口令】的 AD 链 → 入库（验脱敏持久化）
        foots = [
            {"id": 1, "access_level": "external", "verdict": "verified", "label": "e", "props": {}},
            {"id": 2, "access_level": "shell", "verdict": "verified", "label": "shell 命令注入",
             "props": {"replay": {"command_template": "curl ...{CMD}"}}},
            {"id": 3, "access_level": "domain_admin", "verdict": "verified", "label": "da svc-sql",
             "props": {"replay": {"verify_command": "secretsdump veritas.lab/webdev:PASSWORD@dc"}}},
        ]
        finds = [{"type": "command-injection", "foothold_id": 2}, {"type": "kerberoast", "foothold_id": 3}]
        strat = m.distill_strategy("http://lab-edge:8080", foots, finds)
        sid = await board.add_strategy("taskA", "http://lab-edge:8080", strat["tags"],
                                       strat["summary"], strat["steps"], strat["max_access"])
        check("add_strategy 返回 id", isinstance(sid, int) and sid > 0, True)

        # 再加一条无关的 web sqli 策略（不同 task/标签）
        await board.add_strategy("taskB", "http://shop:3000", ["sqli", "db_read", "app:shop"],
                                 "sqli：web_user → db_read", [{"access_level": "db_read", "vuln_type": "sqli",
                                  "approach": "web/sqli（注入位置 query）"}], "db_read")

        # 标签检索：command-injection → 命中 AD 那条（且排在前）
        rows = await board.search_strategies(tags=["command-injection", "app:lab-edge"], limit=5)
        check("标签检索命中 AD 策略", any("command-injection" in (r["summary"] or "") for r in rows), True)
        check("标签检索 top1 是重叠最高的 AD 策略", "command-injection" in (rows[0]["summary"] or ""), True)

        # 关键词 ILIKE 检索：sqli → 命中 web 那条
        rows2 = await board.search_strategies(query="sqli", limit=5)
        check("ILIKE 检索命中 sqli 策略", any("sqli" in (r["summary"] or "") for r in rows2), True)

        # exclude_task：排除 taskA 后，command-injection 标签应查不到 AD 那条
        rows3 = await board.search_strategies(tags=["command-injection"], exclude_task="taskA", limit=5)
        check("exclude_task 生效", all(r["task_id"] != "taskA" for r in rows3), True)

        # 脱敏持久化：库里那条 AD 策略绝不含明文口令 / 原始 DCSync 命令
        row = await pool.fetchrow("SELECT * FROM strategies WHERE id=$1", sid)
        blob = str(dict(row))
        check("★库内无明文口令", "PASSWORD" not in blob, True)
        check("★库内无原始 secretsdump 命令", "secretsdump" not in blob, True)
        check("steps 为 JSONB 列表", isinstance(row["steps"], list), True)
        check("tags 为数组且含路径标签", any(str(t).startswith("path:") for t in row["tags"]), True)
    finally:
        await pool.close()
        admin = await asyncpg.connect(ADMIN)
        await admin.execute("DROP DATABASE IF EXISTS veritas_memtest")
        await admin.close()

    print(f"\n{'FAILED '+str(_fail) if _fail else 'ALL PASS'}  (test_memory_db)")
    return 1 if _fail else 0

sys.exit(asyncio.run(main()))
