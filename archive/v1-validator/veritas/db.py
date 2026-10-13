"""Postgres 连接池 + 幂等建表。"""
from __future__ import annotations

import json
import pathlib

import asyncpg

_SCHEMA = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"


async def _init_con(con: asyncpg.Connection) -> None:
    # 让 jsonb 列在读写时自动 dict <-> json，Board 全程用 dict
    await con.set_type_codec(
        "jsonb",
        encoder=lambda v: json.dumps(v, ensure_ascii=False, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )


async def connect(dsn: str) -> asyncpg.Pool:
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, init=_init_con)
    await init_schema(pool)
    return pool


async def init_schema(pool: asyncpg.Pool) -> None:
    sql = _SCHEMA.read_text(encoding="utf-8")
    async with pool.acquire() as con:
        await con.execute(sql)   # 全部 IF NOT EXISTS，可重复执行
