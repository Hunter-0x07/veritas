"""XSS 执行级验证（Playwright）。

只认【真执行】：payload 弹出 dialog，或在顶层文档把唯一 token 写进我们自己的
window.__VERITAS —— 而不是"响应里出现了 payload 字符串"（回显≠执行）。

证据纪律：
  - 先做目标健康检查，基线页面 5xx / 不可达时一律 INSUFFICIENT，杜绝目标异常时误报；
  - 页面本身返回 5xx 的 payload 直接跳过；
  - 不用 window.name 作信号（iframe 内设的是 iframe 的 name，顶层读不到，且易被污染）；
  - Playwright 未安装时 INSUFFICIENT（诚实降级）。
"""
from __future__ import annotations

import uuid
from urllib.parse import quote

import httpx

from .base import ValidationResult, Validator, Verdict


class XssValidator(Validator):
    vuln_type = "xss"

    def _payloads(self, token: str) -> list[str]:
        # 执行后要么弹 dialog（含 token），要么在顶层文档设 window.__VERITAS=token
        return [
            f'<img src=x onerror="window.__VERITAS=\'{token}\'">',
            f'<svg onload="window.__VERITAS=\'{token}\'">',
            f'<img src=x onerror="alert(\'{token}\')">',
            f'<iframe src="javascript:alert(\'{token}\')"></iframe>',
        ]

    async def validate(self, finding: dict, scope, oob) -> ValidationResult:
        tmpl = finding.get("url_template")
        if not tmpl:
            return ValidationResult(Verdict.INSUFFICIENT, {"error": "缺少 url_template"})

        # 健康检查：目标不可用就不可能有可信结论
        base = tmpl.split("#", 1)[0].replace("{payload}", "veritasHealthProbe") or tmpl
        try:
            scope.check(base)
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as hc:
                hr = await hc.get(base)
            if hr.status_code >= 500:
                return ValidationResult(Verdict.INSUFFICIENT,
                                        {"error": f"目标不可用 HTTP {hr.status_code}"},
                                        "目标返回 5xx，无法验证")
        except Exception as e:  # noqa: BLE001
            return ValidationResult(Verdict.INSUFFICIENT, {"error": f"目标不可达: {e}"})

        try:
            from playwright.async_api import async_playwright
        except Exception:  # noqa: BLE001
            return ValidationResult(
                Verdict.INSUFFICIENT,
                {"error": "playwright 未安装：pip install playwright && playwright install chromium"})

        token = "VX" + uuid.uuid4().hex[:12]
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                for payload in self._payloads(token):
                    url = tmpl.replace("{payload}", quote(payload))
                    try:
                        scope.check(url)
                    except Exception as e:  # noqa: BLE001
                        return ValidationResult(Verdict.INSUFFICIENT, {"error": f"scope: {e}"})

                    page = await browser.new_page()
                    fired = {"dialog": False}

                    async def _on_dialog(d):
                        if token in (d.message or ""):
                            fired["dialog"] = True
                        await d.dismiss()

                    page.on("dialog", _on_dialog)
                    bad_status = False
                    try:
                        resp = await page.goto(url, wait_until="load", timeout=15000)
                        if resp and resp.status >= 500:
                            bad_status = True
                        await page.wait_for_timeout(1800)
                        marker = await page.evaluate("() => window.__VERITAS || ''")
                    except Exception:  # noqa: BLE001
                        marker = ""
                    finally:
                        await page.close()

                    if bad_status:
                        continue  # 页面不可用，这个 payload 不算数
                    executed = fired["dialog"] or (token == str(marker))
                    if executed:
                        return ValidationResult(
                            Verdict.CONFIRMED,
                            {"oracle": "dom_execution", "payload": payload,
                             "signal": "dialog" if fired["dialog"] else "dom_marker"},
                            f"浏览器加载 {url} 后 payload 真实执行（{'弹窗' if fired['dialog'] else 'DOM 标记'}）")
            finally:
                await browser.close()

        return ValidationResult(Verdict.INSUFFICIENT,
                                {"tried": len(self._payloads(token))},
                                "所有 payload 均未观测到执行信号（可能已修复或非注入点）")
