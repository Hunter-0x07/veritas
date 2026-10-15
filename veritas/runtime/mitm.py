"""全链路 MITM 留痕（ARTEX 记录型 MITM + 出口代理 + CA 注入）。

在每个 solver 的 Kali 沙箱里起一个记录型 mitmdump 代理，并把 http(s)_proxy 与 CA 注入到
容器环境——这样 curl/sqlmap/python/浏览器等工具的**全部 HTTP 流量**都被透明抓取，成为
每一跳可复现的原始证据（curl 可回放）。流以 JSONL 落在容器内，增量 cat 回来入攻击图。
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging

log = logging.getLogger("veritas.mitm")

# mitmproxy addon：每条响应完成即把请求/响应摘要追加写 JSONL（我们不依赖 .mitm 二进制格式）
_ADDON = r'''
import json
OUT = "/tmp/va_flows.jsonl"
def response(flow):
    try:
        req, resp = flow.request, flow.response
        rec = {
            "method": req.method, "url": req.pretty_url, "host": req.host,
            "status": resp.status_code if resp else None,
            "req_headers": dict(req.headers),
            "req_body": (req.get_text(strict=False) or "")[:4000] if req.raw_content else "",
            "resp_headers": dict(resp.headers) if resp else {},
            "resp_body": (resp.get_text(strict=False) or "")[:4000] if resp else "",
            "ts": req.timestamp_start,
        }
        with open(OUT, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
'''


class MitmRecorder:
    FLOW = "/tmp/va_flows.jsonl"
    ADDON = "/tmp/va_addon.py"
    LOG = "/tmp/va_mitm.log"
    CA = "/root/.mitmproxy/mitmproxy-ca-cert.pem"

    def __init__(self, sandbox, port: int = 8888):
        self.sandbox = sandbox
        self.port = port
        self.started = False
        self._offset = 0  # 已入库行数（增量收流）

    async def start(self) -> bool:
        """起 mitmdump，等代理+CA 就绪后注入代理 env 与 CA 信任。返回是否成功。"""
        if self.started:
            return True
        b64 = base64.b64encode(_ADDON.encode()).decode()
        await self.sandbox.exec(f"echo {b64} | base64 -d > {self.ADDON}")
        await self.sandbox.exec(
            f"rm -f {self.FLOW}; nohup mitmdump -q -s {self.ADDON} "
            f"--listen-host 127.0.0.1 --listen-port {self.port} --set block_global=false "
            f"> {self.LOG} 2>&1 < /dev/null &")
        ready = False
        for _ in range(20):
            rc, _out = await self.sandbox.exec(
                f"test -f {self.CA} && "
                f"(ss -ltn 2>/dev/null | grep -q ':{self.port} ' || grep -qi listening {self.LOG})")
            if rc == 0:
                ready = True
                break
            await asyncio.sleep(0.5)
        if not ready:
            log.warning("MITM 代理未就绪（继续，但可能抓不到流）")
            return False
        # 信任 CA + 注入出口代理 env（sh -lc 登录 shell 会 source /etc/profile.d/*.sh）
        proxy = f"http://127.0.0.1:{self.port}"
        env = (f"export http_proxy={proxy}\nexport https_proxy={proxy}\n"
               f"export HTTP_PROXY={proxy}\nexport HTTPS_PROXY={proxy}\n"
               f"export REQUESTS_CA_BUNDLE={self.CA}\nexport SSL_CERT_FILE={self.CA}\n"
               f"export CURL_CA_BUNDLE={self.CA}\nexport no_proxy=\n")
        env_b64 = base64.b64encode(env.encode()).decode()
        await self.sandbox.exec(
            f"cp {self.CA} /usr/local/share/ca-certificates/mitmproxy.crt 2>/dev/null; "
            f"update-ca-certificates >/dev/null 2>&1; "
            f"echo {env_b64} | base64 -d > /etc/profile.d/va_proxy.sh")
        self.started = True
        log.info("MITM 记录型代理就绪（:%d，全链路 HTTP 留痕 + CA 注入）", self.port)
        return True

    async def collect(self, board, task_id: str, worker_id: str) -> int:
        """增量把容器里的 JSONL 流入攻击图，返回新增条数。"""
        rc, out = await self.sandbox.exec(f"cat {self.FLOW} 2>/dev/null")
        if rc != 0 or not out:
            return 0
        lines = out.splitlines()
        new = lines[self._offset:]
        self._offset = len(lines)
        flows = []
        for ln in new:
            ln = ln.strip()
            if not ln:
                continue
            try:
                flows.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
        n = await board.add_http_flows(task_id, worker_id, flows)
        if n:
            log.info("MITM 收流 %d 条 → 攻击图（worker=%s）", n, worker_id)
        return n
