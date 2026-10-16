<#
  Veritas AD 靶场 —— 真 Windows AD DC 预埋脚本（域 veritas.lab）
  ======================================================================
  为什么是 Windows：Samba AD DC 与 impacket 的 Kerberos TGS 认证器(AES256 会话密钥)
  + DRSUAPI DCSync 根本不兼容（实测 KRB_AP_ERR_INAPP_CKSUM / byte-indices，MIT 客户端却正常），
  Kerberoast→DCSync 这套标准攻击链在 Samba 上跑不通。真 Windows DC 上 impacket 完全正常。
  （Samba 版见 ../dc/，仅作踩坑记录保留。）

  预埋三条到 domain_admin 的路径（与 Samba 版一致，供 solver 自主发现）：
    主链 : svc-sql  配 SPN + 弱密码 'Password1' + ∈ Domain Admins → Kerberoast→crack→secretsdump(DCSync)
    备线 : backup   设 DONT_REQUIRE_PREAUTH + 弱密码 'Autumn2024'  → AS-REP roasting→crack
    硬路 : webdev   对 DC 对象 GenericAll                          → addcomputer→RBCD→S4U→secretsdump DC
    入口凭据(埋在 member 机 /opt/app/config.ini)：webdev / 'Passw0rd!'

  用法（在一台全新 Windows Server 2019/2022 上，以管理员 PowerShell 运行）：
    1) 第一次运行 → 安装 AD DS 角色并把本机提升为 veritas.lab 的域控，然后【自动重启】。
    2) 重启登录后 → 再运行一次本脚本 → 创建弱账号/SPN/ACL（幂等，可重复跑）。
  说明：Claude 的 arm64 Docker 起不了 Windows，本脚本【无法本地验证】，在你 Windows 上跑；
        子命令/策略随 Server 版本略有差异，报错把日志贴回按版本微调（延续 Samba 版 provision.sh 的约定）。
#>

$ErrorActionPreference = 'Stop'

# ── 参数（与 targets/ad-lab/dc/provision.sh 对齐）────────────────────────────
$Realm      = 'veritas.lab'
$NetBIOS    = 'VERITAS'
$DsrmPass   = 'Dsrm!Recovery2024'    # DSRM(目录服务恢复)口令，与攻击无关，仅 promote 需要
$BaseDN     = 'DC=veritas,DC=lab'
# 注：全新林首台 DC 会把【建 VM 时的本机管理员】变成 RID-500 内置域管（Azure 上通常叫 labadmin，
#     不叫 Administrator）。它是 DCSync 的目标账号之一，口令沿用你建 VM 时设的管理员口令，脚本不再重设。

# ── Phase 1：若本机还不是域控 → 安装 AD DS + 提升为新林，然后重启 ───────────────
$isDC = $false
try { $isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4 } catch { $isDC = $false }

if (-not $isDC) {
    Write-Host '[phase1] 安装 AD DS 角色并提升为 veritas.lab 域控（完成后自动重启）...' -ForegroundColor Cyan
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName $Realm `
        -DomainNetbiosName $NetBIOS `
        -SafeModeAdministratorPassword (ConvertTo-SecureString $DsrmPass -AsPlainText -Force) `
        -InstallDns `
        -DomainMode 'WinThreshold' -ForestMode 'WinThreshold' `
        -NoRebootOnCompletion:$false `
        -Force
    # Install-ADDSForest 会触发重启；重启登录后【再跑一次本脚本】进入 Phase 2。
    return
}

# ── Phase 2：创建弱账号 / SPN / 组 / ACL（幂等）──────────────────────────────
Import-Module ActiveDirectory
Write-Host '[phase2] 本机已是域控，开始预埋弱点 ...' -ForegroundColor Cyan

function New-WeakUser {
    param([string]$Sam, [string]$Pass, [string]$Desc)
    $sec = ConvertTo-SecureString $Pass -AsPlainText -Force
    $u = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if ($null -eq $u) {
        New-ADUser -Name $Sam -SamAccountName $Sam -AccountPassword $sec -Enabled $true `
                   -PasswordNeverExpires $true -Description $Desc -ErrorAction Stop | Out-Null
        Write-Host "  + 创建用户 $Sam"
    } else {
        Set-ADAccountPassword -Identity $Sam -Reset -NewPassword $sec
        Set-ADUser -Identity $Sam -Enabled $true -PasswordNeverExpires $true -Description $Desc
        Write-Host "  = 用户 $Sam 已存在，重置口令/属性"
    }
}

# RID-500 内置域管：按 SID 结尾 -500 定位（名字随建 VM 方式而变，Azure 上常是 labadmin，不叫 Administrator）。
# 不重设其口令（沿用建 VM 时的管理员口令，避免把你自己 RDP 锁在外面）；仅报告它是 DCSync 的目标之一。
$rid500 = Get-ADUser -Filter * -Properties SID | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
if ($rid500) {
    Write-Host "  = RID-500 内置域管 = $($rid500.SamAccountName)（DCSync 目标之一；口令沿用你建 VM 时的管理员口令）"
} else {
    Write-Host '  ! 未找到 RID-500 账号（异常，检查域是否正常 provision）' -ForegroundColor Yellow
}

# 低权域用户
New-WeakUser -Sam 'jdoe'   -Pass 'Summer2024' -Desc 'John Doe'
New-WeakUser -Sam 'webdev' -Pass 'Passw0rd!'  -Desc 'Web dev (delegated rights on DC — RBCD bait)'

# 主链：Kerberoastable 服务账号 svc-sql（SPN + 弱密码 + ∈ Domain Admins）
New-WeakUser -Sam 'svc-sql' -Pass 'Password1' -Desc 'SQL Service Account'
Set-ADUser -Identity 'svc-sql' -ServicePrincipalNames @{ Replace = 'MSSQLSvc/lab-dc.veritas.lab:1433' }
# 让服务票走 RC4(etype 23) → Kerberoast 出 $krb5tgs$23$，john/hashcat 秒破（模拟遗留服务账号，真实常见）
Set-ADUser -Identity 'svc-sql' -Replace @{ 'msDS-SupportedEncryptionTypes' = 4 }
Add-ADGroupMember -Identity 'Domain Admins' -Members 'svc-sql' -ErrorAction SilentlyContinue
Write-Host '  + svc-sql: SPN=MSSQLSvc/lab-dc.veritas.lab:1433, RC4-roastable, ∈ Domain Admins'

# 备线：AS-REP roastable 用户 backup（DONT_REQUIRE_PREAUTH + 弱密码）
New-WeakUser -Sam 'backup' -Pass 'Autumn2024' -Desc 'Backup operator'
Set-ADAccountControl -Identity 'backup' -DoesNotRequirePreAuth $true
Write-Host '  + backup: DONT_REQUIRE_PREAUTH（AS-REP roastable）'

# 硬路：webdev 对 DC 计算机对象 GenericAll（RBCD 埋点）
$dc = Get-ADDomainController -Discover | Select-Object -First 1
$dcDN = (Get-ADComputer -Identity $dc.Name).DistinguishedName
# dsacls 授 GenericAll（GA）给 VERITAS\webdev
& dsacls.exe "$dcDN" /G "$NetBIOS\webdev:GA" | Out-Null
Write-Host "  + webdev GenericAll on $dcDN（RBCD 入口）"

# ms-DS-MachineAccountQuota=10（RBCD 需新建机器账号；Windows 默认即 10，显式确认）
Set-ADDomain -Identity $Realm -Replace @{ 'ms-DS-MachineAccountQuota' = 10 } -ErrorAction SilentlyContinue

Write-Host ''
Write-Host "[done] 域 $Realm 预埋完成。DC=lab-dc.$Realm  administrator 口令已设。" -ForegroundColor Green
Write-Host '校验：'
Write-Host '  Get-ADGroupMember "Domain Admins"            # 应含 svc-sql'
Write-Host '  Get-ADUser svc-sql -Properties ServicePrincipalNames,msDS-SupportedEncryptionTypes'
Write-Host '  Get-ADUser backup  -Properties DoesNotRequirePreAuth'
