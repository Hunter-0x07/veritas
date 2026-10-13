"""Postgres 连接池 + 幂等建表。"""
from __future__ import annotations

import json
import pathlib

import asyncpg

_SCHEMA = pathlib.Path(__file__).resolve().parent.parent / "schema.sql"


async def _init_con(con: asyncpg.Connection) -> None:
    await con.set_type_codec(
        "jsonb",
        encoder=lambda v: json.dumps(v, ensure_ascii=False, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )


async def connect(dsn: str) -> asyncpg.Pool:
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, init=_init_con)
    async with pool.acquire() as con:
        await con.execute(_SCHEMA.read_text(encoding="utf-8"))
    return pool
