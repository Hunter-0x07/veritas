# Samba AD DC —— Linux 上的域控（非真 Windows；不含 AD CS，ADCS/ESC 不可演，见 README 边界）
#
# 基础镜像必须是 ubuntu:24.04（Samba 4.19.5）。曾用 debian:bookworm-slim（Samba 4.17.12），
# 其 KDC 在 TGS 阶段的 PAC/enctype 校验与 impacket 不兼容：所有 Kerberos 操作（Kerberoast /
# AS-REP / S4U / DCSync）都报 `KRB_AP_ERR_INAPP_CKSUM`，整条域链被堵死（已实测坐实）。
# 4.19.5 修复了这个问题。换基础镜像后务必 `docker compose down -v` 清掉旧域数据卷再 build。
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# samba(AD DC) + 管理/诊断工具；ldb-tools 用于 provision 阶段直接改 sam.ldb（设 UAC / RBCD ACL）
# 关键坑：samba-ad-provision 带 AD schema，samba-dsdb-modules 带 AD 专用 ldb 模块（samba_secrets 等）；
#        这两个都是 samba 的 recommends，--no-install-recommends 会漏装 → provision 崩在 secrets.ldb。
RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules \
        smbclient winbind libnss-winbind krb5-user \
        ldb-tools ldap-utils dnsutils procps iproute2 \
    && rm -f /etc/samba/smb.conf \
    && rm -rf /var/lib/samba/private \
    && rm -rf /var/lib/apt/lists/*

COPY provision.sh /provision.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /provision.sh /entrypoint.sh

# DNS/Kerberos/LDAP/SMB/GC：域攻击面
EXPOSE 53 88 135 139 389 445 464 636 3268 3269
CMD ["/entrypoint.sh"]
