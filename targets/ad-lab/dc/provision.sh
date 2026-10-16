#!/bin/bash
# Veritas AD 靶场预埋 —— Samba AD DC 域 veritas.lab
#
# 预埋三条到 domain_admin 的路径（全部 Samba 兼容，供 solver 自主发现）：
#   主链 : svc-sql  配 SPN + 弱密码 'Password1' + ∈ Domain Admins  → Kerberoast→crack→secretsdump(DCSync)
#   备线 : backup   设 DONT_REQUIRE_PREAUTH + 弱密码 'Autumn2024'  → AS-REP roasting→crack
#   硬路 : webdev   对 DC 对象 GenericAll                          → addcomputer→RBCD→S4U→secretsdump DC
#   入口凭据(埋在 member 机 /opt/app/config.ini)：webdev / 'Passw0rd!'
#
# 注：本脚本在用户终端 docker build/up 时执行（Claude 沙箱无 Samba，无法本地验证）。
#     samba-tool 子命令随 Samba 版本略有差异；build/up 若报错，把日志贴回即按版本微调。
set -euo pipefail

REALM="VERITAS.LAB"
DOMAIN="VERITAS"
ADMINPASS="Adm1nP@ss2024!"          # administrator 口令 —— DCSync 最终要抓到的目标 hash 之一
SAMDB="/var/lib/samba/private/sam.ldb"
BASE_DN="DC=veritas,DC=lab"

echo "[provision] samba-tool domain provision ..."
rm -f /etc/samba/smb.conf
samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="$ADMINPASS"

echo "[provision] 低权域用户 ..."
samba-tool user create jdoe   'Summer2024'  --given-name=John --surname=Doe
samba-tool user create webdev 'Passw0rd!'   --description="Web dev (delegated rights on DC — RBCD bait)"

echo "[provision] 主链：Kerberoastable 服务账号 svc-sql（弱密码 + ∈ Domain Admins）..."
samba-tool user create svc-sql 'Password1' --description="SQL Service Account"
samba-tool spn add "MSSQLSvc/lab-dc.veritas.lab:1433" svc-sql
samba-tool group addmembers "Domain Admins" svc-sql

echo "[provision] 备线：AS-REP roastable 用户 backup（DONT_REQUIRE_PREAUTH + 弱密码）..."
samba-tool user create backup 'Autumn2024' --description="Backup operator"
# userAccountControl = NORMAL_ACCOUNT(512) | DONT_REQUIRE_PREAUTH(4194304) = 4194816
ldbmodify -H "$SAMDB" <<EOF
dn: CN=backup,CN=Users,${BASE_DN}
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
EOF

echo "[provision] 硬路：webdev 对 DC 对象 GenericAll（RBCD 埋点）..."
DC_DN="CN=LAB-DC,OU=Domain Controllers,${BASE_DN}"
# 取 webdev 的 SID（Samba ldbsearch 对 objectSid 一般直接输出 S-1-5-... 字符串）
WEBDEV_SID="$(ldbsearch -H "$SAMDB" "(sAMAccountName=webdev)" objectSid 2>/dev/null \
              | sed -n 's/^objectSid: //p' | tr -d '[:space:]')"
if [ -n "${WEBDEV_SID:-}" ] && printf '%s' "$WEBDEV_SID" | grep -q '^S-1-'; then
    # (A;;GA;;;SID) = Allow GenericAll → 可写 msDS-AllowedToActOnBehalfOfOtherIdentity（RBCD）
    samba-tool dsacl set --objectdn="$DC_DN" --sddl="(A;;GA;;;${WEBDEV_SID})"
    echo "[provision]   -> GenericAll on $DC_DN 已授予 webdev ($WEBDEV_SID)"
else
    echo "[provision]   !! 取 webdev SID 失败（got='${WEBDEV_SID:-}'）——RBCD ACL 未设，请 build 后手动核对" >&2
fi

# ms-DS-MachineAccountQuota 默认 10（RBCD 需新建机器账号）；显式确认，老版本无此子命令则忽略
samba-tool domain settings account_machine_join_quota 10 >/dev/null 2>&1 || true

echo "[provision] 完成。域=$REALM  DC=lab-dc.veritas.lab  administrator 口令已设。"
