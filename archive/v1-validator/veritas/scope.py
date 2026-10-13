"""授权边界校验 —— Phase 0 安全底线，越界直接拒绝。

对外请求前必须 check()；新发现的越界目标可入图但标 in_scope=False，不自动攻击。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .config import ScopeCfg


class ScopeError(PermissionError):
    """目标不在授权范围内。"""


class Scope:
    def __init__(self, cfg: ScopeCfg):
        self.domains = [d.lower().lstrip(".") for d in cfg.domains]
        self.nets = []
        for c in cfg.cidrs:
            try:
                self.nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    def _host_ok(self, host: str) -> bool:
        host = host.lower()
        # 域名后缀匹配（example.com 命中 a.example.com）
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        # IP / CIDR 匹配
        for ip in self._resolve(host):
            for net in self.nets:
                if ip.version == net.version and ip in net:
                    return True
        return False

    @staticmethod
    def _resolve(host: str) -> list[ipaddress._BaseAddress]:
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass
        out = []
        try:
            for fam, _, _, _, sa in socket.getaddrinfo(host, None):
                try:
                    out.append(ipaddress.ip_address(sa[0]))
                except ValueError:
                    continue
        except socket.gaierror:
            pass
        return out

    def allows(self, url: str) -> bool:
        host = urlparse(url if "://" in url else "http://" + url).hostname
        return bool(host) and self._host_ok(host)

    def check(self, url: str) -> None:
        if not self.allows(url):
            raise ScopeError(f"目标越界，拒绝执行: {url}")
