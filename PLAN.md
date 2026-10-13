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

- **M4 · 规模化 + 结论可信**
  完成定义：并行 solver 舰队（分解+难点冗余重试）+ trace 协作 + Observer 监督 + 全链路 MITM 留痕 + kill chain 报告（带每一跳 PoC 与复现）。能并行多目标、结论不误报、报告可交付。可对 HackerOne 风格的授权目标跑。

- **M5 · 长程 + 工程化**
  完成定义：冷图压缩落地（控长程成本）+ 跨 run 策略记忆（向量库复用成功 kill chain）+ 分级自主/审批门（横向/破坏性 HITL）+ 多 provider + kill chain 可视化回放。

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
