"""edge 服务：故意留命令注入漏洞的最小 web（仅用于授权靶场）。

/ping?host=... 把 host 直接拼进 shell 命令 → 命令注入。
attacker 经此拿到 edge 执行能力（shell@edge），再经 edge 扫内网 / ssh 横向。
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def index():
    return ("Edge Diagnostics Service\n"
            "Try: /ping?host=internal-host\n")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # 漏洞：host 未过滤直接进 shell（命令注入）
    cp = subprocess.run(f"ping -c 1 -W 2 {host}", shell=True,
                        capture_output=True, text=True, timeout=30)
    return "<pre>" + (cp.stdout or "") + (cp.stderr or "") + "</pre>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
