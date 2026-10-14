"""知识包加载：skills/*.md，按名加载到 agent 上下文（preload 或按需 load_skill）。"""
from __future__ import annotations

import pathlib

_DIR = pathlib.Path(__file__).resolve().parent / "skills"


def available() -> list[str]:
    if not _DIR.is_dir():
        return []
    return sorted(p.stem for p in _DIR.glob("*.md"))


def load(name: str) -> str | None:
    f = _DIR / f"{name}.md"
    return f.read_text(encoding="utf-8") if f.exists() else None
