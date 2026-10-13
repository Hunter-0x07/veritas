"""CLI 入口：  python -m veritas run --target http://localhost:3000"""
from __future__ import annotations

import argparse
import asyncio
import logging

from .config import Config
from .engine import run as run_engine
from .scope import ScopeError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="veritas", description="证据驱动的自主渗透系统（W1 骨架）")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="对目标发起一次自主测试")
    r.add_argument("--config", default="dispatch.yaml", help="配置文件（默认 dispatch.yaml）")
    r.add_argument("--target", required=True, help="目标 URL（须在授权 scope 内）")
    r.add_argument("--mock", action="store_true", help="强制 mock 模式（无需 LLM key）")
    r.add_argument("--instruction", help="人类提示（live 模式注入给 agent，如 API 结构/测试账号）")
    r.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%H:%M:%S")

    cfg = Config.load(args.config)
    if args.mock:
        cfg.llm.mode = "mock"

    try:
        task_id, report_path, cost = asyncio.run(run_engine(cfg, args.target, args.instruction))
    except ScopeError as e:
        print(f"✗ 授权校验失败：{e}")
        return 2
    print(f"\n✓ 任务 {task_id} 完成")
    print(f"  报告: {report_path}")
    if cost:
        print(f"  成本: ${cost:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
