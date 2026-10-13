# Veritas — 证据驱动的自主渗透系统设计

> 代号 Veritas（"真相"，可改）。一句话：**用状态空间搜索找路径，用确定性证据定真伪**。
>
> 可视化版：claude.ai Artifact（私有）— https://claude.ai/artifact/VDEfiNQxMUWjwjmV8nCdq9
> 日期：2026-10-12 · 融合 Cairn / ARTEX / BreachWeave / Strix + 2026 前沿研究

Veritas 继承 Cairn 的搜索哲学、ARTEX 的双图与链路稳定、BreachWeave 的监督与上下文治理、Strix 的工具链与闭环，再补上四家共同缺失的那一层——**证据信任与确定性验证**。这是 2026 前沿研究的共识，也与 BAS/检测验证"攻击必须可证"的要求天然契合。

---

## 一、先立靶子：要系统性消灭的 9 个已知失败模式

好的架构是"为消灭失败而设计"。这 9 条全部有调研/实战支撑。

| # | 失败模式 | 来源 |
|---|---|---|
| F1 | 幻觉发现 / 误报（LLM 自称打下了） | XBOW「精度优先」、Survey 可靠性 |
| F2 | 盲信环境证据 / 蜜罐欺骗 | EnvTrustBench、ATOBench、PentestGPT v2 弱点 |
| F3 | 目标侧 prompt injection 污染规划层 | JEV-Laya、LOCKIFY |
| F4 | 探索不足 / 无目的重复游走（**头号杀手**） | CVE-Bench（55–80% 失败）、MazeRunner |
| F5 | 长程状态丢失 / 上下文膨胀 | HPTSA、"Staying on the Attack Path"、BreachWeave |
| F6 | 多步利用链错序 / 断链 | ARTEX todolist 动机 |
| F7 | 主观早停 / 结束不客观 | BreachWeave 报告驱动、Observer |
| F8 | 不可审计 / 不可复现 / provenance 缺失 | LOCKIFY TRUSTGRAPH |
| F9 | 安全失控（越权、沙箱逃逸、高危动作） | CAI 自主性分级、ARTEX 审批门 |

## 二、顶层哲学

1. **渗透 = 有向状态空间搜索**（起点已知、目标已知、路径未知）——不写固定剧本。（继承 Cairn）
2. **推理层与验证层彻底分离**：LLM 负责"提出假设、探索路径"，证据真伪由确定性 oracle 判定，**LLM 永不自证**。（XBOW / JEV-Laya 的核心教训）
3. **一切目标输出默认不可信**：观察是"证据"不是"指令"，先过信任边界再进上下文。（EnvTrustBench / LOCKIFY）

## 三、分层架构

```
┌──────────────────────────────────────────────────────────────┐
│ L0 控制平面 Orchestrator   任务/资产/预算/并发/生命周期/自主性档位 │
├──────────────────────────────────────────────────────────────┤
│ L1 规划层 Planner(唯一意图生成)  读全局态势+覆盖度, 维护攻击计划todolist│
│ L2 执行层 Worker ×N          领单条意图, 真实工具, 上下文隔离, 即停  │
│ L3 监督层 Observer(纠偏/防早停/防膨胀) + Failure-Review(失败复盘回灌)│
│ L4 验证层 Validator          确定性oracle + 对抗投票 → 三态结论     │
├──────────────────────────────────────────────────────────────┤
│ 横切 ① 证据信任总线  provenance + untrusted标记 + 注入筛查 + 新鲜度 │
│ 横切 ② 共享状态  双图(资产真值图·全局 / 探索血缘图·每任务) + 向量记忆│
│ 横切 ③ 知识层  技能包(侦察/漏洞/协议/技术栈/云) 按需load            │
│ 横切 ④ 安全层  沙箱隔离 + 审批门 + HITL + 自主性分级 + 授权边界      │
│ 横切 ⑤ 可观测  全链路留痕 + 攻击流可视化 + 回放 + 统计/成本          │
└──────────────────────────────────────────────────────────────┘
```

### 数据原语（比四家多了对"证据状态"的显式建模）

| 原语 | 含义 | 谁产 | 关键约束 |
|---|---|---|---|
| Asset | 资产真值（全局去重/打分/父子） | 程序计算 | agent 只提原始信息 |
| Intent | 探索方向 | Planner | 带 novelty / 期望价值评分 |
| **Observation** | 原始观察 | Worker | **强制带 provenance + untrusted 标记** |
| **Fact** | 已核验事实 | 升级而来 | Observation 经交叉验证才升级 |
| **Finding** | 漏洞 | Validator 裁决 | 三态：Confirmed / Refuted / **Insufficient** |
| Hint | 人类注入 | Human | 随时注入，下轮吸收 |
| Strategy | 成功策略 | 系统沉淀 | 入向量记忆，跨任务复用 |

## 四、十大核心机制（每条标注解决哪个 F，融合自谁）

- **M1 攻击面发现与优先级打分** `F4` — 子域扩展 + 按 WAF/状态码/重定向/认证表单/可达端点/技术栈打分排序；SimHash + 截图 imagehash 去重克隆/staging。*新增，源自 XBOW。*
- **M2 覆盖度驱动的 frontier** `F4` — Planner 把"资产图覆盖率"当显式优化目标；Intent 带 novelty + 期望价值分，队列去重。*升级自 ARTEX 双图 + CVE-Bench 结论。*
- **M3 规划/执行上下文隔离 + 共享结构化状态** `F5 F6` — planner 每次全新会话，连续性靠持久双图 + 共享 todolist（串行链逐步派发）。解决 HPTSA 的上下文争抢。*融合 HPTSA + ARTEX。*
- **M4 证据信任边界** `F2 F3 F8` — 目标响应进上下文前过非自回归分类器做注入筛查；全链路 provenance；观察当证据不当指令；来源存疑则 fail-closed。*新增，源自 JEV-Laya / LOCKIFY / EnvTrustBench——四家最大空白。*
- **M5 确定性验证 oracle + 三态结论** `F1 F2` — Finding 升级必须过该漏洞类型的确定性校验（布尔差分 / headless 执行 / 带外回连）；对抗投票；显式保留 Insufficient；目标自述永不作证据。*融合 XBOW validators + JEV-Laya 三态 + ATOBench。*
- **M6 Observer + Failure-Review 双监督** `F4 F5 F7` — Observer 旁路纠偏（防偏移/膨胀/过早结束）；Failure-Review 把失败路径复盘成负面知识回灌。*融合 BreachWeave Observer + MazeRunner。*
- **M7 客观结束条件** `F7` — 目标 proven（经 L4）或全资产覆盖 + 强制交报告（无发现也交，含失败边界）。*源自 BreachWeave 报告驱动 + asset_hash。*
- **M8 跨任务策略记忆** `效率` — 成功 PoC / 利用链 / 环境指纹入向量库（pgvector），新任务先检索复用。*源自 PentAGI pgvector 策略库。*
- **M9 上下文压缩与过程级检索** `F5` — 工具输出先摘要入上下文；冷数据冷存可检索；worker 间以"执行过程"为粒度互查。*融合 ARTEX compaction/coldgraph/trace + BreachWeave 降噪。*
- **M10 分级自主 + 安全层** `F9` — 每任务容器沙箱；高危动作经审批门 + HITL；CAI 式自主性档位，高危强制降档人工。*融合 Strix 沙箱 + ARTEX guard/intercept + CAI autonomy levels。*

## 五、相对四家 + 前沿的差异化

| 能力支柱 | Cairn | ARTEX | BreachWeave | Strix | Veritas |
|---|:--:|:--:|:--:|:--:|:--:|
| 状态空间搜索 / 黑板 | ● | ● | ● | ○ | ● |
| Planner/Worker 分离 | ● | ● | ● | ● | ● |
| Observer 监督 | ○ | ○ | ● | ○ | ● |
| **确定性验证 oracle** | ○ | ◐ | ○ | ◐ | ● |
| **证据信任/抗注入/反蜜罐** | ○ | ○ | ○ | ○ | ● |
| 攻击面打分调度 | ○ | ◐ | ○ | ◐ | ● |
| 跨任务策略记忆 | ○ | ○ | ○ | ◐ | ● |
| 工具链完整度 | ○ | ● | ◐ | ●● | ● |
| 闭环到修复/CI | ○ | ◐ | ○ | ●● | ◐ |

一句话：**Veritas = Cairn 的脑 + ARTEX 的骨 + BreachWeave 的免疫系统 + Strix 的手 + 2026 研究的"证据信任中枢"**。

## 六、落地路线

- **Phase 0 · MVP（2–4 周）**：双图黑板 + Planner/Worker + 容器沙箱 + 1–2 个确定性 validator（SQLi 带外 / XSS headless）+ 强制报告。先把"能自主打下 + 结果可信"跑通。（详见 [PHASE0.md](./PHASE0.md)）
- **Phase 1**：证据信任边界 + 注入筛查 + 覆盖度 frontier + 攻击面打分。
- **Phase 2**：Observer + Failure-Review + 向量记忆 + 上下文压缩 + 攻击流可视化回放。
- **Phase 3**：多 provider 抽象 + CI/CD + 复测 agent + 分级自主 + 多租户/认证。

## 七、给 BAS / 检测验证方向的落点

- **M5 确定性 oracle** ≈ BAS 里"攻击成功信号必须有 ground-truth 证据"——带外回连、指纹校验正是判定"真命中 vs 假命中"的那套。
- **M4 反 overtrust / 反蜜罐** ≈ 真实检测环境里区分"真绕过防御"还是"落进诱捕 / WAF 假响应"——BAS 结论可信度的命门。
- **M7 强制报告含失败边界** ≈ BAS 要求"未触发也要留痕"，让攻击覆盖度与防御有效性都可审计。

## 八、调研依据与延伸阅读

- XBOW · The Road to Top 1 — https://xbow.com/blog/top-1-how-xbow-did-it/
- HPTSA · Teams of LLM Agents can Exploit Zero-Day Vulnerabilities — https://arxiv.org/abs/2406.01637
- CVE-Bench — https://arxiv.org/abs/2503.17332
- AutoPenBench — https://arxiv.org/pdf/2410.03225
- EnvTrustBench · When Agents Overtrust Environmental Evidence — https://arxiv.org/abs/2605.08828
- ATOBench · 目标证据撒谎时如何验证 — https://arxiv.org/html/2608.12996v1
- JEV / Laya · Calibrated Decision Models — https://arxiv.org/pdf/2609.28940
- MazeRunner / PentestAgent — https://arxiv.org/pdf/2608.14216
- A Survey of LLM-Driven Penetration Testing — https://arxiv.org/pdf/2607.02605
- CAI · Cybersecurity AI（自主性分级） — https://arxiv.org/abs/2504.06017
