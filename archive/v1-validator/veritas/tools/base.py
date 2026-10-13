"""工具接口。每次调用返回 structured + raw + provenance；raw 一律标 untrusted。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    structured: dict                      # 程序可信的提取结果
    raw: str                              # 原始输出（untrusted）
    provenance: dict = field(default_factory=dict)

    @staticmethod
    def make(source_tool: str, request: Any, structured: dict, raw: str) -> "ToolResult":
        return ToolResult(
            structured=structured,
            raw=raw,
            provenance={"source_tool": source_tool, "request": request,
                        "ts": time.time(), "untrusted": True},
        )


class Tool:
    name: str = "tool"
    description: str = ""

    def schema(self) -> dict:
        """LiteLLM/OpenAI function-calling schema（live 模式用）。"""
        return {"type": "function", "function": {
            "name": self.name, "description": self.description,
            "parameters": {"type": "object", "properties": {}}}}

    async def run(self, **kwargs) -> ToolResult:  # pragma: no cover - interface
        raise NotImplementedError
