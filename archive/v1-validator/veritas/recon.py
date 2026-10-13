"""攻击面发现 —— 消灭 F4 探索不足的核心。

对 SPA（如 Juice Shop）尤其关键：API 端点藏在 JS bundle 里，首页 HTML 看不到。
做两件事：① 抓首页引用的 JS bundle，正则抽 rest/api 路径；② 探测常见路径。
发现的端点由 worker 写进资产图，planner 据覆盖度自动派新意图继续探。
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# 抽 rest/ api/ graphql/ 开头的路径（bundle 里常无前导斜杠）
_API_RE = re.compile(r'(?<![\w/])((?:rest|api|graphql)/[A-Za-z0-9_\-/]{1,60})')
_STATIC = re.compile(r'\.(js|css|png|jpe?g|svg|ico|woff2?|ttf|map|html?)$', re.I)

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/ftp",
    "/metrics", "/swagger.json", "/api-docs", "/graphql", "/admin",
]


def _clean(path: str) -> str:
    p = "/" + path.strip().strip("/")
    p = re.split(r'[?#\'"`\\]', p)[0]          # 去 query/引号残留
    return p.rstrip("/.")


async def discover_endpoints(scope, base_url: str, max_eps: int = 25) -> list[dict]:
    base = base_url.rstrip("/")
    texts: list[str] = []
    endpoints: list[dict] = []
    seen: set[str] = set()

    async with httpx.AsyncClient(timeout=20, follow_redirects=True, verify=False) as c:
        # 1) 首页 HTML
        try:
            if scope.allows(base_url):
                r = await c.get(base_url)
                texts.append(r.text)
                scripts = _SCRIPT_SRC.findall(r.text)
            else:
                scripts = []
        except Exception:  # noqa: BLE001
            scripts = []

        # 2) JS bundle（SPA 的 API 路由藏在这里）
        for s in scripts[:8]:
            js = urljoin(base + "/", s)
            try:
                if scope.allows(js):
                    texts.append((await c.get(js)).text)
            except Exception:  # noqa: BLE001
                continue

        # 3) 从 HTML + JS 文本里抽 API 路径
        for t in texts:
            for m in _API_RE.findall(t):
                path = _clean(m)
                if len(path) < 3 or _STATIC.search(path):
                    continue
                url = base + path
                if url not in seen:
                    seen.add(url)
                    endpoints.append({"url": url, "source": "js"})
                    if len(endpoints) >= max_eps:
                        break

        # 4) 常见路径探测（只保留存在的）
        for p in COMMON_PATHS:
            url = base + p
            if url in seen:
                continue
            try:
                if scope.allows(url):
                    rr = await c.get(url)
                    if rr.status_code < 400:
                        seen.add(url)
                        endpoints.append({"url": url, "source": "common", "status": rr.status_code})
            except Exception:  # noqa: BLE001
                continue

    return endpoints[:max_eps]
