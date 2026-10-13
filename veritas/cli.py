"""CLI 入口：  python -m veritas run --mock --target http://localhost:3000"""
from __future__ import annotations

import argparse
import asyncio
import logging

from .config import Config
from .core.engine import run as run_engine


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="veritas", description="自动化渗透引擎（v2）")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="对目标发起一次自主渗透")
    r.add_argument("--config", default="dispatch.yaml", help="配置文件（默认 dispatch.yaml）")
    r.add_argument("--target", help="目标（覆盖配置）")
    r.add_argument("--goal", help="目标访问级别（覆盖配置），如 shell / root / domain_admin")
    r.add_argument("--mock", action="store_true", help="强制 mock 模式（无需 LLM / 真实目标）")
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
    goal = args.goal or cfg.goal

    task_id, report_path, reached, max_acc = asyncio.run(run_engine(cfg, args.target, args.goal))
    mark = "✅" if reached else "⚠️"
    print(f"\n{mark} 任务 {task_id} 完成 · 最终访问级别 {max_acc}（goal={goal}）")
    print(f"  kill chain 报告: {report_path}")
    return 0 if reached else 1


if __name__ == "__main__":
    raise SystemExit(main())
