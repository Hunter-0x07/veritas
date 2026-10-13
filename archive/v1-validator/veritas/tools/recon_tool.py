"""recon 工具：供 live 模式的 LLM 主动调用，发现 API 端点。

（worker 探测 root 资产时也会自动跑同一套 recon 把端点写进资产图，这里是让
LLM 能对任意页面再补一次侦察。）
"""
from __future__ import annotations

import json

from ..recon import discover_endpoints
from ..scope import Scope
from .base import Tool, ToolResult


class ReconTool(Tool):
    name = "recon"
    description = "抓取页面及其 JS bundle、枚举常见路径，发现隐藏的 API 端点（对 SPA 尤其有效）。"

    def __init__(self, scope: Scope):
        self.scope = scope

    def schema(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description,
            "parameters": {"type": "object", "properties": {
                "url": {"type": "string", "description": "要侦察的页面 URL（授权范围内）"},
            }, "required": ["url"]}}}

    async def run(self, url: str, **kw) -> ToolResult:
        self.scope.check(url)
        eps = await discover_endpoints(self.scope, url)
        structured = {"count": len(eps), "endpoints": [e["url"] for e in eps]}
        return ToolResult.make(self.name, {"url": url}, structured, json.dumps(eps, ensure_ascii=False))
