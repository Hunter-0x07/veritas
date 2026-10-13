"""load_skill 工具：按需加载知识包（侦察/漏洞测试要点）到 agent 上下文。

知识外置成技能包，而不是焊死在 system prompt 里——让 agent 遇到对应场景再加载，
既省上下文又可扩展（对应 DESIGN 的横切③ 知识层）。
"""
from __future__ import annotations

import pathlib

from .base import Tool, ToolResult


class SkillTool(Tool):
    name = "load_skill"

    def __init__(self, skills_dir: str):
        self.dir = pathlib.Path(skills_dir)

    def _names(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.stem for p in self.dir.glob("*.md"))

    @property
    def description(self) -> str:
        return "加载一个知识包到上下文。可用: " + ", ".join(self._names())

    def schema(self) -> dict:
        names = self._names()
        return {"type": "function", "function": {
            "name": self.name, "description": self.description,
            "parameters": {"type": "object", "properties": {
                "name": {"type": "string", "enum": names,
                         "description": "知识包名"},
            }, "required": ["name"]}}}

    async def run(self, name: str, **kw) -> ToolResult:
        f = self.dir / f"{name}.md"
        if not f.exists():
            return ToolResult.make(self.name, {"name": name},
                                   {"error": "no such skill", "available": self._names()}, "")
        content = f.read_text(encoding="utf-8")
        return ToolResult.make(self.name, {"name": name}, {"loaded": name}, content)
