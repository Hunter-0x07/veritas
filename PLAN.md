# Veritas v2 — 自动化渗透引擎（设计蓝图）

> 本文件是待 review 的设计计划副本，尚未开始写代码。

## Context

Veritas v1 做成了"漏洞验证器"（确认 SQLi/XSS 三态裁决就结束），偏离了目标——用户要的是**真正的自动化渗透**：能挖 HackerOne、能从 Web 打进内网横向。v1 已归档到 `archive/v1-validator/`，主线清空重来。

本蓝图综合了：外部前沿（Incalmo S&P'26 的高层攻击抽象、XBOW 的协调舰队+creative/deterministic 原则）+ 本地四家实战实现（Cairn 的状态空间搜索哲学、ARTEX 的双图/CAS/串行 todolist/冷图/trace 协作、Strix 的沙箱执行器/知识包/报告 pipeline、BreachWeave 的 Observer 监督），经过取舍而非堆砌。

---

## 一、诚实的闭环判断：这东西能做到什么程度

不画饼。基于 XBOW/Incalmo 的真实结果 + 行业现状：

| 能力 | 能闭环吗 | 诚实的实际效果 |
|---|---|---|
| **Web 漏洞挖掘（挖 HackerOne 主体）** | ✅ 能 | 达到**活跃 bug hunter 的广度与速度**——自动发现+PoC 验证 SQLi/XSS/SSRF/IDOR/认证类，中低危有稳定产出。XBOW 验证了商业价值，但其"#1"有水分（实际赏金 <$4 万、大量 medium/low）。**顶尖高危/复杂业务逻辑仍需人。** |
| **Web 利用链推进**（dump→拿凭据→提权） | ✅ 能 | 单机 web 上能走完"发现→利用→提权"串行链，这是 v1 缺的核心。 |
| **Web→内网横向** | ⚠️ 半 | Incalmo 证明在**已知 N-day + 仿真/靶场**里能部分闭环（9/10 部分成功）；**真实企业内网**（EDR/分段/未知环境）目前**全行业**都做不到可靠闭环。现实目标 = 靶场/CTF/已知路径的自动横向 + 辅助红队。 |
| **后渗透/提权** | ⚠️ 半 | 已知提权（sudo 错配、已知 CVE）可自动；复杂提权需人。 |

**真瓶颈（全行业未解，不是我们的锅）**：横向/后渗透可靠性、高危逻辑漏洞发现、EDR 规避、真实环境不确定性（蜜罐/动态防御）、成本（深推理×多 solver×长程）。

**定位**：做一个"**自动化广度漏洞发现 + PoC 验证 + 已知路径横向**"的引擎——挖 HackerOne 这条线能产生真实价值且可闭环；全自动打穿真实域控是能力边界，设计上为人机协同（HITL）留好接口，而不是假装全自动。

---

## 二、第一性原理与核心抽象

**渗透 = 在「攻击图」上做状态空间搜索：节点是立足点/资产/凭据/战利品，边是 kill-chain 动作（利用漏洞→权限跃迁），目标是达成某个访问级别或拿到某份数据。**

进展用**访问级别**度量，不用"发现几个漏洞"：
`external < recon < web_user < web_admin < db_read < shell < root < domain_admin`

---

## 三、架构（分层）

```
┌─ Operator（人）─ 目标 / scope(含网段) / 授权 / HITL 审批 ───────────┐
├─────────────────────────────────────────────────────────────────┤
│ Coordinator 协调者（持久、唯一规划者）                              │
│   · 读攻击图当前态势 → 按价值(访问跃迁收益)排序前沿                 │
│   · 持有跨唤醒串行利用链 todolist（软状态，图为权威）   ← ARTEX     │
│   · 事件驱动 + debounce 唤醒；Observer 旁路监督防偏移/早停 ← BreachWeave│
├─────────────────────────────────────────────────────────────────┤
│ Solver 舰队 ×N（并行，每个 fresh session，CAS 领取前沿）  ← ARTEX+XBOW│
│   默认按【分解】并行（不同资产/不同 kill-chain 步）                 │
│   难点卡住时才启局部【冗余重试】（同一机会多次独立尝试取成功）← XBOW│
│   舰队间 search_all_worker_traces 共享过程/凭据（排除自己）← ARTEX  │
├─────────────────────────────────────────────────────────────────┤
│ Executor 执行层（混合策略，见 §五）                                │
│   A. 确定性动作执行器：Scan/CrackHash/Login/LateralMove/OOB验证    │  ← Incalmo
│   B. 自由沙箱执行器：Web 漏洞挖掘与利用（agent+shell+代理+浏览器）  │  ← Strix
│   两者结果都归一化写回攻击图；"利用成功"确定性判定 ← XBOW creative/deterministic
├─────────────────────────────────────────────────────────────────┤
│ Attack Graph 攻击图状态服务（= 黑板，Stigmergy）        ← Cairn+ARTEX│
│   双图：资产真值图(全局,DB唯一索引去重,upsert 自动串父子)           │
│        + 推进血缘图(每任务,kill-chain 边) + 锚点溯源               │
├─────────────────────────────────────────────────────────────────┤
│ 横切：知识层(markdown skills,preload+按需load ←Strix) ·            │
│   记录型MITM全链路留痕+出口代理+CA注入(←ARTEX) · 容器沙箱(Kali,←Strix)│
│   · 冷图压缩(←ARTEX) · 分级自主/审批门(←ARTEX) · 多provider(LiteLLM)│
│   · 跨run策略记忆(向量库,净新增) · 证据纪律/反蜜罐(←v1)            │
└─────────────────────────────────────────────────────────────────┘
```

**推进循环**：立足点 → Coordinator 排序前沿、派机会 → Solver 领取(CAS)、决策 → Executor 落地并确定性判定成功 → 攻击图长出新立足点/凭据/主机 → 新立足点触发内网 recon → 循环直到达成 goal 或前沿耗尽。

---

## 四、攻击图数据模型

沿用 ARTEX 的双图+锚点，扩展出访问推进语义：

**资产真值图（全局，DB 唯一索引去重 + ON CONFLICT merge，父子靠 upsert side-effect）**
节点类型：`root_domain / subdomain / ip / service / endpoint / host / credential / session`
边：`contains`（域→IP→服务→端点）、`can_access`（凭据→主机/服务）、`pivots_to`（主机→内网主机）

**推进血缘图（每任务）**
节点：`goal / foothold / opportunity / finding / loot / hint`
边：`spawns / exploits / yields / proves / derived_from / covers(冷图)`

**锚点**：血缘节点 ↔ 资产，记"谁碰过谁"（溯源，不 gate 可见性）。

**关键原语**
- `Foothold`：label + access_level + location（进展度量，初始 external）
- `Opportunity`：from_foothold + target_asset + kind + 期望跃迁（Coordinator 产，Solver 领）
- `Credential` / `Loot`：战利品，推进与横向的燃料
- `Finding`：可走的边的证据（不是终点）

---

## 五、关键设计抉择（取 / 舍 / 融合 + 理由）

| 抉择点 | 决定 | 理由 |
|---|---|---|
| **决策/执行分层** | **混合**：确定性动作用 Incalmo 式声明执行器；Web 利用用 Strix 式自由沙箱 | Web 漏洞利用千变万化，固定动作集表达不了（给 agent 沙箱+知识包）；横向/扫描/破解/登录模式固定、确定性强、是状态骨架（声明式+确定性执行器，省上下文、可审计、多主机管得住）。**按动作确定性程度分治，不是强塞两套。** |
| **舰队策略** | **分解派生为主**（ARTEX），**局部冗余重试**为辅（XBOW） | 渗透是广度/多目标/多主机，本质是分解并行；冗余并行(N 个打同一点)成本高、浪费，只在单点难题卡住时用。XBOW 说舰队累积错误——ARTEX 的"每轮 fresh session + 图为权威状态 + trace 互查"已解决，不必全量冗余。 |
| **意图领取** | **条件 UPDATE CAS**（ARTEX），弃 SKIP LOCKED | 横向多 worker 抢同一前沿，`UPDATE WHERE state=open`+RowsAffected 无死锁无长事务，配 ResetRunning 崩溃重领，比行锁更适合。 |
| **执行器工具** | **沙箱 shell + 薄知识包**（Strix），不逐个 wrap 工具 | Strix 验证过：给 Kali 沙箱+shell，LLM 跑 CLI，知识包指导，比为每个扫描器写 wrapper 灵活得多。Caido 透明代理的 `repeat_request`=原子攻击动作直接借。 |
| **验证能力** | **降级为 Executor 的"动作成功判定"**，不是主流程 | v1 的确定性验证/反蜜罐没白做——变成"利用是否真成功"的判定（拿到 shell？dump 到数据？带外回连？），服务推进而非列漏洞。 |
| **上下文治理** | **冷图 digest 压缩**（ARTEX，纯算法可移植）+ 结构化安全 checkpoint（Strix） | 多主机横向让图爆炸，冷图"live 分支保 hot、settled 折叠、签名复用、commit 前 liveness recheck"是长程省成本关键。 |
| **跨 worker 信息** | `search_all_worker_traces` 设为**一等公民**（横向默认开，凭据关键词加索引） | 横向最大痛点是侦察/凭据产物不共享，ARTEX 默认不开给 worker，横向场景要默认开。 |
| **砍掉/后置** | SARIF/auto-fix/PR、公司资产归属、Web UI、MCP、retester 复测 | 这些是 AppSec 修复闭环/企业资产管理/运营设施，对"挖洞+渗透"内核不是必需，后期按需加，不进 P0。 |

---

## 六、路线图（按"完成什么样"定义，非时间）

> 每个里程碑 = 一个可验证的能力状态。做完一个才进下一个。

- **M0 · 骨架能推进**
  完成定义：攻击图（双图 schema）+ Coordinator + Solver + Executor 接口齐备；**mock 演示完整 kill chain**（external → web_user → 拿 credential → internal_recon 发现内网 host → lateral_move → shell@host），攻击图正确长出节点、goal 达成即停、输出 kill chain。不接真实目标、不烧 token。**证明"推进"这个灵魂跑通。**

- **M1 · 单机 Web 能真打**
  完成定义：external recon（子域/端口/服务/web 资产测绘）+ 自由沙箱 Web Solver（Kali 沙箱 shell + Caido 代理 + 浏览器 + web 知识包）能对一个真实 web 靶标**自主发现并利用漏洞**，利用成功后产出真实 foothold/credential 写回攻击图。靶标：Juice Shop。

- **M2 · Web 利用链闭环**
  完成定义：能走完多步串行链 `SQLi→dump→拿 hash→crack→用凭据登录→提权到 web_admin`，由 Coordinator 的共享 todolist 按依赖调度（不错序）。证据纪律在线（利用成功确定性判定，反蜜罐）。

- **M3 · 多主机横向闭环**
  完成定义：从 web 立足点做 internal recon 发现内网主机 + 声明式横向动作执行器（凭据复用/ssh/smb/winrm）+ pivot 代理，攻击图长出内网主机并拿到 `shell@内网host`。靶标：自搭 web+内网 docker 网络靶场（或 Incalmo MHBench 式）。**这是"从 web 到内网横向"的验收点。**

- **M4 · 规模化 + 结论可信** — ✅ 三刀落地 + live 整链验证通过（2026-10-15）
  完成定义：并行 solver 舰队（分解+难点冗余重试）+ trace 协作 + Observer 监督 + 全链路 MITM 留痕 + kill chain 报告（带每一跳 PoC 与复现）。能并行多目标、结论不误报、报告可交付。可对 HackerOne 风格的授权目标跑。
  **已落地（2026-10-15，三刀）**：
  - 第一刀·规模化：Coordinator 同阶段按资产分解 fan-out（多 web 资产/多内网主机各出前沿）+ CAS 并行领取 + 每 solver 独享按需启动的 Kali 沙箱；难点卡住按 `MAX_ATTEMPTS` 冗余重试、超限放弃；`search_worker_traces` 跨 worker 共享侦察/凭据线索。
  - 第二刀·结论可信：证据确定性验证层（`core/verifier.py`）给每个立足点/凭据判 `verdict`，`max_access`/goal 只认 `verified`（防幻觉、不误报）；Observer（`core/observer.py`）旁路监督失速/鬼打墙/早停·误报（确定性）。
  - 第三刀·留痕：每个沙箱起记录型 `mitmdump` 代理 + CA 注入（`runtime/mitm.py`），全链路 HTTP 透明抓取入 `http_flows`，报告每跳 curl 可复现；新增 `repeat_request` 原子重放。
  - kill-chain 树：同一 transition 内多立足点按(访问级别,上报顺序)串父子，还原 pivot 链（`edge→internal`），不再拍平成平行分支。
  **验证状态**：mock 闭环 + 针对性单测（舰队/重试/trace/验证器/Observer/pivot 链）+ 真 MITM 管线测全绿；**live 整链已通过**——GLM 单 solver 打穿 lateral-lab（lab-edge `/ping` 命令注入→root RCE→ssh 横向 internal-host 拿 `shell`+flag），2 立足点+deploy 凭据全过证据验证(`verdict=verified`)、Observer 零告警、MITM 抓 54 条真流量入库、报告每跳 curl 可复现（task `6df1fb958887`）。遗留：**多"根目标"并行**（当前是单任务内多资产 fan-out）；成本显示 $0 是 litellm 对 glm 定价的已知 bug（实际用量 ~284K in / 10.6K out）。

- **M4.5 · AD 域横向（打到访问模型顶点 domain_admin）** — ✅ live 通过（2026-10-16）
  完成定义：真 Windows AD DC 上，GLM solver 自主从 web 立足点经域凭据发现 → Kerberoast / DCSync 把访问级别推到 `domain_admin`，证据可复现、结论不误报。
  **已落地**：靶场 `targets/ad-lab`（入口 member Flask `/ping` 命令注入 + config.ini 藏域凭据；DC = 云 x64 Windows Server 2022，`windows-dc/provision.ps1` 预埋 svc-sql[SPN+弱密码+∈Domain Admins]/backup[AS-REP]/webdev[对 DC 对象 GenericAll]）；沙箱补 impacket/netexec；知识包 `active-directory.md`；web_solver 域优先引导 + 证据纪律。
  **live（task `497336b6a14c`）**：external→root(member 命令注入)→domain_admin（Kerberoast svc-sql → john 破 `Password1` → DCSync 抓 `labadmin:500`(RID-500) + `krbtgt` NT hash）；两条 domain_admin 立足点 + 4 凭据全 `verified`、Observer 零告警、132K in tokens 一轮直达。
  **踩坑（血的，务必记）**：① **Samba AD DC 与 impacket 根本不兼容**——Kerberos TGS 认证器对 AES256 会话密钥报 `KRB_AP_ERR_INAPP_CKSUM`、DRSUAPI DCSync 报 `byte indices`/`ERROR_SUCCESS`，而 MIT 客户端(kinit/kvno)一切正常（证明是 impacket×Samba 的锅、非 KDC）；跨 impacket 0.12/0.13/0.14dev、Py3.12/3.14 一致复现，强制 RC4（账号 `msDS-SupportedEncryptionTypes=4` / 全局 `kerberos encryption types=legacy`）也改不动 TGT 会话密钥 enctype。→ **Samba 不可演 Kerberoast/DCSync，必须真 Windows Server**（Apple Silicon 本地跑不了 x64 Windows Server → 云）。② Azure 新林首台 DC 把建 VM 的本机管理员变成 RID-500 内置域管（叫 `labadmin`，域里**无** `Administrator`）→ 判据认 RID-500 不认字面名。③ ADCS/ESC 系列本期不做（Samba 无 CA；真演需单独 Windows + AD CS）。

- **M5 · 长程 + 工程化 + 面向未知靶场的证明模型**
  完成定义：冷图压缩落地（控长程成本）+ 跨 run 策略记忆（向量库复用成功 kill chain）+ 分级自主/审批门（横向/破坏性 HITL）+ 多 provider + kill chain 可视化回放 + **proof-of-effect verifier（验"世界"不验"报告"）**。

  ### 冷图压缩（cold compaction）——控长程 token 成本（🚧 第一刀已落地 2026-10-22）
  **为什么**：token 成本全在 `web_solver` 的 agentic loop——每步把 tool 结果塞进 `messages`、每次 `llm.chat` 重发整段历史 → 无限增长（实测单 run ~1M in tokens）。**关键洞察**（与 ARTEX 不同）：ARTEX 的 LLM 每轮看「图总览」、冷子图折成 digest 节点缩总览；veritas 的 LLM 只看自己的**转录**（攻击图在 Postgres、靠 `search_worker_traces` 按需取），故冷图压缩 = **转录压缩**。
  **已落地**：`llm/compaction.py`（纯函数 `compact_messages`）——转录超阈值（≈50K tokens）就把中段旧 round-trip 折成**确定性 digest**（每 tool_call 压成「命令→输出尾」一行 + 指向 `search_worker_traces` 恢复原文），保留 system+初始任务+最近 N 轮热前沿，折到低水位去抖。**按完整 round-trip 折叠**保 tool_call 配对合法（不留悬空 tool）；**零额外 LLM 成本**（确定性滚动）；只动转录、不动 DB 攻击图/战果。`web_solver` loop 每次 `llm.chat` 前调用。借 ARTEX coldgraph 原则（折冷/留热前沿/去抖低水位），digest 用确定性（而非 LLM 摘要，契合控成本 + 避免"谁压谁验"）。**验证**：17 确定性单测（no-op / 折叠后有界 / 结构合法 tool_call 配对 / 保前沿 / digest 滚动行+指向检索 / 再压缩合并不累积 / 60 步循环转录有界 peak<1.5×阈值）+ prober 49 零回归。**后续**：checkpoint 断点续跑、阈值 config 化、LLM 摘要式 digest（可选开关）。

  ### 分级自主 / 审批门（HITL）+ scope 真接入 executor——碰真外部目标前的安全闸（✅ 已落地 2026-10-24）
  **为什么**：引擎即将碰真·HackerOne 授权外部目标，但有个**明确安全漏洞**——`core/engine.py` 构造 solver 时
  `build_registry("live", …)` **没传 `scope`** → web_solver 拿到 `scope=None` → 已存在的越界守卫永不触发，且
  `ScopeCfg` 根本没有 `allows_cmd` 方法。实测（task `6661273c36a0`，goal=root）GLM 被 config.ini 里的域凭据勾引，
  往已关机的云 DC 与 Docker 网关 `192.168.65.x` 撞了十几次——全在 scope 外、无人拦。
  **已落地**：建 `veritas/safety/` 包（PLAN §七规划的 `scope · approval · autonomy`）。
  - **scope 真接入**（`safety/scope.py` 纯函数 + `ScopeCfg.allows_cmd` 委托）：从命令抽【连接目标】主机/IP
    （**所有 IPv4/IPv6 字面量一律抽**——堵实测事故的高信号；URL 只取 authority，`?redirect=http://evil.com`
    这类 query 内嵌 URL 与 `--data`/`-H` 旗标值里的 FQDN 不抽，避免误杀开放重定向类合法请求），比对 domains +
    CIDR：域内放行、域外拒绝、抽不到主机的本地命令放行；**单标签内网名**（容器名 `lab-edge`）无法 CIDR 校验→放行
    不误杀横向，**多标签外部 FQDN** 未匹配→拒绝；loopback 恒放行；domains/cidrs 都空=不强制。engine 把 `cfg.scope`
    一路传进 `build_registry`→web_solver，越界把明确提示回给 LLM + 落 `activity(gate=scope_denied)`。**prober 也受
    scope 约束**（点名要补）：`Prober(scope=…)`，nonce 回环 / 重认证 / 重跑 DCSync / 9 类 web 探针的目标向量越界→
    降级 INCONCLUSIVE（绝不 refuted），例外是 `_oob_poll`（查引擎自托管监听器，非目标）。
  - **分级自主 / 审批门**（`safety/autonomy.py`）：`classify(cmd)` 把 shell 命令按破坏性/噪声分
    benign / file_write / file_delete / destructive / broad_scan / bruteforce（噪声档 low/medium/high 与 prober
    safe-probe 对齐复用，不另造）；`AutonomyPolicy` 的 `mode=auto` 按 `probe.authorization` 推导（lab→full_auto
    全放行 / external→approval 破坏性需审批）。当前引擎全自动无人在环 → approval 下 `on_gated=deny`（**fail-closed
    默认**）：破坏性/大范围扫描/在线爆破执行前拦截、回提示给 LLM 换招、落 `activity(gate=needs_approval)`、Observer
    `conclude` 交叉核 flag；`on_gated=allow` 给受监督 run 的 fail-open 选项（放行+留痕）。审批点=executor 执行命令处；
    真正的交互式【暂停→operator 逐条批准→恢复】UI 留后续。纪律：sandbox 内 scratch 写 / 窄扫描 / 单文件 rm / 读命令
    不误杀（只拦明确破坏性/大范围/爆破）。报告加「安全闸」小节列出被拦/放行动作供人工复核。
  **验证**：`tests/safety/` 三套确定性单测（纯 `.venv/bin/python`，无 pytest/网络依赖）全绿——`test_scope`（36 例：越界
  IP/Docker 网关/多标签外部 FQDN/云元数据端点拒绝，内网横向/子域/单标签/本地命令/loopback 放行，payload 内嵌 URL 不误杀，
  空 scope 放行）、`test_autonomy`（classify 各类 + fail-closed/fail-open/full_auto 裁决 + mode 推导）、`test_wiring`
  （async + 假 sandbox/board 不调 GLM：越界命令被拦且沙箱从未被调用、合法横向放行、破坏性按策略放/拦、prober 越界探针
  降级且不触沙箱）。**prober 对 scope=None 零行为变化**（现有 49 探针单测不传 scope→守卫不触发）。live（交用户终端跑·烧
  token）复验 GLM 越界命令落 `gate=scope_denied`、合法内网不误杀待补。血缘：ARTEX 分级自主/审批门。

  ### 证明模型（proof-of-effect verifier）——面向未知靶场的结论可信
  **为什么**：M4 的 `verifier.py` 验的是「solver 自述 evidence ↔ 命令输出的字符串重叠」——声称和证据都由 LLM 挑，本质是**验"报告"不验"世界"**。后果：调 prompt 让模型把 evidence 写成 verifier 想要的样子就能变绿 = **过拟合某个模型的输出格式**，再跑一次也只证明"模型输出符合预期"，而非"攻击真发生"。要挖 HackerOne / 上未知靶场（项目定位第一性），必须把验证锚到**世界**。
  **原则**：verdict 由系统从【已记录的真实世界底物】(`activity` 的 exec/rc/out、`http_flows`/MITM) 按**每个访问级别的"举证义务"**自行重新推导；solver 的 evidence/location 只当线索/锚点。三态收敛（借 strix 的 closure discipline）：`verified`（义务达成）/ `refuted`（世界里有明确反证，保守触发）/ `unproven`（open_proof_gap：不计入进展，但记录上报、绝不冒充成功也不偷偷丢）。证据强度阶梯：用成功的凭据 > 效果痕迹(proof-of-effect) > 高熵密文在真实输出里+凭据佐证 > location 真跑过 > 字符串重叠(最弱)。
  **血缘**：strix `counterevidence`/`fix_verification`（闭合纪律 + "什么不算安全证明" + proof-of-effect）、ARTEX（确定性断言为准、LLM 审查仅辅助且会过度概括、防篡改）、Cairn（状态空间达成判定）；XBOW 闭源仅作概念参考（creative·deterministic）。**不是照抄**——它们没有现成的攻击 oracle，按 veritas 的"访问图 + 已记录世界底物"重新设计。
  - **Stage 1 · 验世界（✅ 已落地 2026-10-16）**：`core/verifier.py` 重写——按级别举证义务从真实输出自推导：`domain_admin`=DCSync 真 dump 到 RID-500 内置域管/`krbtgt` 行（或一条 verified 的 NT hash 出现在真实 dump 里佐证）；`root`=`uid=0(`；`shell`=`uid=\d+(`；`location` 抽裸主机名/IP 对 rc=0 命令逐字命中（修掉旧版整串匹配对格式敏感的脆弱）；evidence 字符串重叠降为最弱兜底。加 `refuted` 态（凭据被拿去认证且输出明确失败→refuted，保守）。`solver._apply` 先判凭据、收集 verified 高熵密文供立足点佐证。`observer`/`report` 跟上三态。**真数据回归**：用上一条 AD live（`ee5da75bda5d`）的真实记录跑新 verifier，`domain_admin`/`root`/`shell` 从 unverified→verified（来自真实 DCSync 的 `labadmin:500:…` 与 `uid=0` 输出，**非 LLM 措辞**），两条不可溯源的凭据正确留 `unproven`。
  - **Stage 2 · 主动证明/反证（✅ 已落地 2026-10-16）**：新增持沙箱的 `core/prober.py`——在 verifier 判定前，由执行器（持本 solver 沙箱）对 solver 刚上报的战果发起**只有真拿下才能通过**的主动探针，拿确定性的证成/证伪；verifier 保持纯函数、只接收 `ProbeResult` 当【数据】，**主动结论优先于 Stage 1 被动推导**（proven→verified / refuted→refuted / inconclusive→回落被动），职责干净可测（决策 A：不让 verifier 持沙箱）。三类探针按访问向量：① **nonce 回环**（shell/root）——引擎现场生成随机 nonce 经该立足点访问向量回显，root 要求 nonce 与 `uid=0` 在**同一次探针响应**里（**按主机限定**，修掉 Stage 1"uid=0 出现在任何输出就算 root"的松点）；② **重认证**（credential）——引擎亲自拿凭据跑 `nxc smb`，`[+]/Pwn3d!`→proven、`[-]/LOGON_FAILURE`→refuted（不信 solver 自述"我破出来了"）；③ **重跑 DCSync**（domain_admin）——授权靶场内重跑一次 DCSync，认 RID-500/krbtgt 行→proven。`web_solver` 的 `report_foothold` 加 **`replay` 字段**（决策 B：显式可重放 PoC——shell/root 给含 `{CMD}` 占位符的 `command_template`、domain_admin 给可直接重跑的 `verify_command`），prober 优先用 replay、其次从 traces 反推。**safe-probe 策略（一等公民，决策 C/D）**：主动重探按噪声/破坏性分 low(nonce 回环·幂等) / medium(重认证) / high(重 DCSync) + 探针预算；`authorization=external`（默认·保守）**只放 low**，medium/high 降级为【被动 proof-of-effect + 可复现 PoC + LLM-judge 辅助评级（标 `llm-judged` 低信任档·Observer 交叉核·**绝不单独抬成 verified**）】；`authorization=lab` 开各级。**第一性**：真实目标是 HackerOne 这类授权外部目标（限速/检测/ToS 不能随便重活），本地靶场只是试验台，故 safe-probe + 外部"低噪声 + 可复现 PoC + LLM-judge"是核心主路，靶场重探只是最易实现的特例。**验证**：21 条确定性单测（假沙箱喂罐装输出，覆盖 proven/refuted/inconclusive + 按主机限定 + 策略降级 + 预算封顶）全绿；**live 回归**（真 Kali 沙箱 + 真云 Windows DC `203.0.113.10`，复用 AD 金数据 `497336b6a14c` 的 DC/凭据）**7/7 全绿**——nonce 回环证 member RCE(root)、引擎重认证证 svc-sql、重跑 DCSync 证 domain_admin，**证伪**伪造口令（真 DC 认证失败）与伪造 RCE（向量打静态页 nonce 不回显），外部策略下 low(nonce) 仍主动探、medium(重认证) 正确降级。血缘：strix `counterevidence`/proof-of-effect（主动找反证、"什么不算安全证明"）+ ARTEX 确定性断言为主 / LLM 仅辅助。
  - **Stage 3 · 未知靶场证明模型（🚧 第一刀已落地 2026-10-22：注册表骨架 + LLM-judge 闭环）**：按漏洞/访问类建"举证义务注册表"；写不出确定性义务的新效果，要 solver 交**可复现 PoC（MITM 请求+响应）**，再上 **LLM-judge 仅作辅助评级**（标"llm-judged"低信任档，Observer 交叉核）。**确定性永远是脊梁**——否则就是"谁验证验证器"。
    - **已落地**：① `core/obligations.py` **举证义务注册表**——把 Stage 1/2 硬编码的 shell/root/domain_admin 义务（`uid=…(`/`uid=0(`/DCSync RID-500·krbtgt）迁成声明式 `ObligationSpec{key,desc,proof,active,noise}`，verifier 的 proof-of-effect 改为**查表**（单一真源、零行为变化，27 单测回归绿）；`has_deterministic(key)` 是"有无确定性义务"的岔路开关。② **LLM-judge 闭环**：对**无确定性义务的类**（web_user/web_admin/db_read/业务逻辑，`probe_foothold` 返回 None）或被 safe-probe 降级的高价值声称，executor 收**可复现 PoC**（replay 配方 + 关联 MITM 原始请求/响应）→ `prober.llm_judge` 评级 → 写 `props.probe_judge`（`trust=llm-judged` 低信任档）；**verdict 永远由 verifier 的确定性路决定，LLM-judge 绝不驱动 verified**。③ **Observer 交叉核**：只有 llm-judged 支撑（无确定性证据）的立足点一律 flag `llm_judged`、标"需人工复核"。默认 `probe.llm_judge=false`（opt-in）。验证：27 确定性单测回归 + LLM-judge 闭环【假-LLM 罐装评级】7/7（web 类走 LLM-judge 岔路→标低信任→verdict 仍 unproven 不冒充→Observer flag）；真 GLM 评级质量待一次 live 确认（opt-in 烧 token）。
    - **Cut 2a · 确定性脊梁扩到 web 漏洞面（✅ 已落地 2026-10-22）**：注册表 + prober 加 4 类【确定性】web 探针（都经沙箱 curl→MITM 留痕+scope，引擎自选标记/挑战经注入点回环）：**ssti**（注入引擎自选两数之积，响应出现乘积=真求值；表达式字面回显=未求值→反证）、**sqli**（借归档 v1 三 oracle：报错型 break`'`vs 平衡`''`、认证绕过 token 差分、布尔差分 + union 把引擎 nonce 经 DB 带回）、**lfi**（读到 /etc/passwd 的 `root:…:0:0:` 结构）、**open_redirect**（3xx Location 恰为引擎自选唯一 URL=真控；指向自身=反证）。纪律：回显 payload 串不算证据；验不出一律 unproven（绝不写 refuted）。修正：sqli/ssti/lfi 探针**跟随重定向**取末段真实响应（很多站点 30x 到规范/登录页），open_redirect 不跟随以看 3xx。`replay` 扩 web 字段（probe_type/url/param/method/injection/base_params），`runtime/oob.py` 预埋 `OOBProvider`/`NoopOOB`（Cut 2b 接真监听）。**验证**：prober 单测扩到 39/39（含 4 类 proven/refuted/inconclusive + verifier 主动证成）；**live 9/9**（真沙箱 curl 打真 HTTP 靶：四类真阳 proven、/reflect 反证、/safe 不冒充、307→跟随取末段）。
    - **Cut 2b · OOB canary + SSRF/XXE（✅ 已落地 2026-10-22）**：`runtime/oob_listener.py` 自托管 HTTP canary 监听（`/c/<token>` 记命中、`/hits/<token>` 查询）+ `runtime/oob.py` 的 `HttpOOB`；prober `_probe_ssrf`（注入引擎自选 canary URL→poll 命中=proven）、`_probe_xxe`（带外部实体的 XML→poll）；未配 OOB/未命中→inconclusive（出网可能被过滤，不写反证）。config `probe.oob_url` + engine 建 HttpOOB/NoopOOB。验证：单测 + **OOB live 4/4**（真监听 + 真 SSRF/XXE 靶：目标回连 canary→proven、无回连/未配→inconclusive）。DNS OOB 与真实 interactsh 接入留后续。
    - **Cut 2c · XSS 执行级 + 访问级别基线差分（✅ 已落地 2026-10-22）**：`_probe_xss`（借 v1：引擎进程内 headless Playwright 加载注入 URL，payload 真执行把引擎 token 写进顶层 window / 弹 token dialog，非回显；chromium 未就绪诚实降级）；`_probe_authn`（web_user/web_admin：带获得会话访问受保护资源 vs 匿名基线差分）；`db_read` 由 sqli 探针覆盖。验证：单测 + **live 4/4**（host Playwright 打真反射靶→DOM 标记真执行 proven、转义靶 inconclusive；沙箱 curl 打容器靶 /admin 基线差分 proven）。
    - **Cut 2d · 确定性 IDOR（✅ 已落地 2026-10-22）**：`_probe_idor`——用【自己的会话】读【他人对象】，拿到只属于他人的唯一标记(`other_marker`，由掌握另一账号的 solver 给)→越权确证；有访问控制(403)→inconclusive。验证：单测 + **live 2/2**（无访问控制 /object 读到 SECRET_victim→proven、/object_safe 403→inconclusive）。
    - **web 漏洞面小结**：确定性脊梁已覆盖 rce/ssti/sqli(db_read)/lfi/open_redirect/ssrf/xxe/xss/web_user/web_admin/idor。真正写不出确定性义务的新效果（业务逻辑/竞态/复杂访问控制）才留 LLM-judge 低信任兜底。**后续**：DNS-OOB 与真实 interactsh、盲注时间 oracle、把沙箱镜像补 chromium（让 XSS 走沙箱而非引擎主机、统一 MITM 留痕）。

---

## 七、代码结构（新）

```
Projects/veritas/
  veritas/
    core/        attack_graph(board) · coordinator · solver · state(access模型) · events
    executors/   deterministic/(scan,crack,login,lateral,oob) · freeform/(web_solver)
    tools/       sandbox_shell · http_proxy(caido式) · browser · oob_canary
    recon/       external · internal
    knowledge/   skills/*.md(frontmatter) + loader(preload+按需)
    runtime/     docker 沙箱(Kali 镜像)
    report/      kill_chain 报告 + PoC 固化
    safety/      scope(网段) · approval(审批门) · autonomy(分级)
    llm/         provider(LiteLLM) · compaction(冷图+checkpoint)
    cli.py
  schema.sql     双图 + 访问推进语义（幂等建表）
  dispatch.yaml  目标/scope/goal/llm/runtime
```

可直接移植/参考的实证来源（已深读）：ARTEX `db/schema.sql`、`agent/coldgraph.go`、`agent/planner.go`、`db/exploration.go`（CAS 领取）、`agent/tools.go`（trace 检索）、`traffic/traffic.go`（MITM）；Strix `runtime/session_manager.py`、`tools/proxy/`、`skills/__init__.py`、`report/`、`config/models.py`。

---

## 八、验证方式

- **M0**：`python -m veritas run --mock`，断言攻击图长出 external→…→shell 的 kill chain，报告含完整路径，goal 达成退出。
- **M1-M2**：对本地 Juice Shop，live 模式自主拿到 web foothold + credential + 走完利用链；人工核对 PoC 可复现。
- **M3**：自搭多主机 docker 靶场（web 容器 + 内网容器 + 共享网络），验收"从 web 打进内网拿 shell"。
- **M4**：多目标并行跑，检查无误报、报告 kill chain 完整、成本可控。

---

## 九、刻意不做（防 scope 膨胀）

SARIF/auto-fix/PR、SAST 白盒修复闭环、公司资产归属/外部资产同步、Web 管理 UI（M5 前只 CLI+run 目录）、MCP 生态、retester 复测、EDR 规避——均非内核，后期按需，不进 M0-M3。
