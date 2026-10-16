"""member 服务：域内成员机上的最小诊断 web，故意留命令注入（仅用于授权靶场）。

/ping?host=... 把 host 直接拼进 shell → 命令注入。
RCE 后在 /opt/app/config.ini 能读到连域的 webdev 凭据 → 从沙箱对 DC 打 AD。
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def index():
    return ("Veritas Corp — Host Diagnostics Service\n"
            "Try: /ping?host=lab-dc.veritas.lab\n")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # 漏洞：host 未过滤直接进 shell（命令注入）
    cp = subprocess.run(f"ping -c 1 -W 2 {host}", shell=True,
                        capture_output=True, text=True, timeout=30)
    return "<pre>" + (cp.stdout or "") + (cp.stderr or "") + "</pre>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
