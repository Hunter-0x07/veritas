"""工具沙箱：攻击工具在隔离容器里执行（Strix 式 shell-as-executor）。

执行器不逐个 wrap 工具，而是给它一个容器 shell，直接跑 CLI（nmap/sqlmap/curl/python…）。
M1 用 --network host 以便直达 Juice Shop 与内网；真实对抗环境再收紧。
"""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("veritas.sandbox")


class SandboxError(RuntimeError):
    pass


class Sandbox:
    def __init__(self, name: str, image: str = "veritas-sandbox:latest", network: str = "host"):
        self.name = name
        self.image = image
        self.network = network
        self.started = False

    async def _docker(self, *argv: str, timeout: float = 60) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            "docker", *argv,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return 124, "(timeout)"
        return proc.returncode or 0, out.decode(errors="replace")

    async def start(self) -> str:
        """启动沙箱容器（幂等：若同名已存在先清掉）。"""
        await self._docker("rm", "-f", self.name)
        rc, out = await self._docker(
            "run", "-d", "--name", self.name, "--network", self.network,
            "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", self.image,
            timeout=120)
        if rc != 0:
            raise SandboxError(f"沙箱启动失败: {out}")
        self.started = True
        log.info("沙箱 %s 启动（image=%s network=%s）", self.name, self.image, self.network)
        return out.strip()

    async def exec(self, cmd: str, timeout: float = 180) -> tuple[int, str]:
        """在沙箱里执行一条 shell 命令，返回 (退出码, 合并输出)。"""
        if not self.started:
            raise SandboxError("沙箱未启动")
        return await self._docker("exec", self.name, "sh", "-lc", cmd, timeout=timeout)

    async def stop(self) -> None:
        await self._docker("rm", "-f", self.name)
        self.started = False
