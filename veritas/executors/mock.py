"""M0 脚本化执行器：按 opportunity.kind 产出跃迁，演示一条完整 kill chain：

external → (initial_access) web_user → (web_exploit) web_admin
        → (internal_recon) 发现内网 host → (lateral_move) shell@内网host

真实执行器（自由沙箱 Web Solver / 声明式横向动作）在 M1+ 逐个替换本文件。
不接真实目标、不烧 token——只证明"推进"这个灵魂跑通。
"""
from __future__ import annotations

from .base import ExecResult, Executor, Transition


class MockExecutor(Executor):
    kinds = ("initial_access", "web_exploit", "internal_recon", "lateral_move")

    async def execute(self, opp, board, task_id: str) -> ExecResult:
        kind = opp["kind"]
        payload = opp["payload"] or {}
        loc = payload.get("location", "target")

        if kind == "initial_access":
            return ExecResult(True, "攻破 Web 登录（SQLi 认证绕过）→ web_user + admin hash", Transition(
                footholds=[{"label": f"web_user@{loc}", "access_level": "web_user", "location": loc,
                            "props": {"evidence": "POST /rest/user/login  email=' OR 1=1-- → 200 返回 admin JWT"}}],
                findings=[{"type": "sqli", "severity": "high",
                           "reproduction": "POST /rest/user/login  email=' OR 1=1--"}],
                credentials=[{"kind": "hash", "username": "admin",
                              "secret": "$2a$10$Vb...redacted", "source": "login SQLi"}],
            ))

        if kind == "web_exploit":
            return ExecResult(True, "提权到 web_admin，dump users 表 → 内网部署凭据", Transition(
                footholds=[{"label": f"web_admin@{loc}", "access_level": "web_admin", "location": loc,
                            "props": {"evidence": "UNION SELECT dump users 表；admin 会话可访问 /api/admin"}}],
                loot=[{"kind": "data", "summary": "users 表 42 行（含内网部署账号 deploy）"}],
                credentials=[{"kind": "password", "username": "deploy",
                              "secret": "Spr1ng!2024", "source": "DB dump"}],
            ))

        if kind == "internal_recon":
            # 发现多台内网主机 → 下一轮 lateral_move 按主机 fan-out，舰队并行横向
            ff = opp["from_foothold"]
            hosts = [("10.0.0.5", ["ssh:22"]), ("10.0.0.6", ["ssh:22", "mysql:3306"]),
                     ("10.0.0.7", ["ssh:22", "smb:445"])]
            return ExecResult(True, f"从 web 立足点扫内网 → 发现 {len(hosts)} 台主机", Transition(
                assets=[{"type": "host", "dedup_key": ip, "reachable_from": ff,
                         "props": {"ip": ip, "services": svc}, "in_scope": True}
                        for ip, svc in hosts],
            ))

        if kind == "lateral_move":
            host = payload.get("host", "10.0.0.5")
            return ExecResult(True, f"用 deploy 凭据 SSH 横向到 {host} → shell", Transition(
                footholds=[{"label": f"shell@{host}", "access_level": "shell", "location": host,
                            "props": {"evidence": f"sshpass -p Spr1ng!2024 ssh deploy@{host} 'id' → uid=1000(deploy)"}}],
            ))

        return ExecResult(False, f"mock 未覆盖 {kind}")
