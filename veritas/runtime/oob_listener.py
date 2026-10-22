"""带外(OOB) canary 监听器 —— Stage 3 Cut 2b 的自托管回连靶（HTTP）。

极小 stdlib HTTP 服务：目标若真发起带外请求打中唯一 token 的路径，就被记下来；
prober 事后 poll 该 token 是否命中 → 命中=确定性证明 SSRF/XXE/盲注真发生（引擎自选 token，
只有目标真回连才可能命中，LLM 造不出）。

放在引擎可达、且【目标也可达】的网络位置（本地：与靶同一 docker 网；真实外部目标：公网 IP /
interactsh）。独立进程运行：`python -m veritas.runtime.oob_listener [port]`。
端点：
  GET /c/<token>      canary（目标回连打这个）→ 记录命中，返回 1x1
  GET /hits/<token>   prober 查询 → "HIT" / "MISS"
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

_HITS: set[str] = set()


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静音
        pass

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/c/"):
            tok = path[3:].strip("/")
            if tok:
                _HITS.add(tok)
            # 1x1 gif，像个正常资源（SSRF 常被当图片/URL 预览抓取）
            self._send(200, b"GIF89a", "image/gif")
        elif path.startswith("/hits/"):
            tok = path[6:].strip("/")
            self._send(200, b"HIT" if tok in _HITS else b"MISS")
        else:
            self._send(404, b"nope")

    do_POST = do_GET
    do_PUT = do_GET


def main(argv=None):
    port = int((argv or sys.argv[1:] or ["8098"])[0])
    HTTPServer(("0.0.0.0", port), _H).serve_forever()


if __name__ == "__main__":
    main()
