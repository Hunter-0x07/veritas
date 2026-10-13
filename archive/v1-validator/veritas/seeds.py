"""mock 模式的候选漏洞种子。

mock 负责"猜哪里可能有洞"，validator 真刀真枪去证——这正是 W2 验收 validator
确定性的方式。默认针对 OWASP Juice Shop 的两个经典注入点。
"""
from __future__ import annotations


def juice_shop_seeds(base: str) -> list[dict]:
    base = base.rstrip("/")
    return [
        {
            "type": "sqli",
            "title": "登录 email 参数 SQL 注入 / 认证绕过",
            "asset": f"{base}/rest/user/login",
            "url": f"{base}/rest/user/login",
            "method": "POST",
            "injection": "json_body",
            "param": "email",
            "base_params": {"email": "test@juice-sh.op", "password": "x"},
            "severity": "critical",
        },
        {
            "type": "sqli",
            "title": "商品搜索 q 参数 SQL 注入（报错 / UNION 型）",
            "asset": f"{base}/rest/products/search",
            "url": f"{base}/rest/products/search",
            "method": "GET",
            "injection": "query",
            "param": "q",
            "base_params": {"q": "apple"},
            "severity": "high",
        },
        {
            "type": "xss",
            "title": "搜索框 DOM XSS",
            "asset": f"{base}/#/search",
            "url_template": f"{base}/#/search?q={{payload}}",
            "context": "dom",
            "severity": "high",
        },
    ]


def default_seeds(base: str) -> list[dict]:
    return juice_shop_seeds(base)
