# Veritas

> 自动化渗透引擎 —— 在**攻击图**上做访问权限推进，能挖 HackerOne，能从 Web 打进内网横向直到域控。

渗透被建模成「攻击图」上的状态空间搜索：节点是立足点 / 资产 / 凭据 / 战利品，边是 kill-chain 动作（利用漏洞 → 权限跃迁），目标是达成某个访问级别或拿到某份数据。进展用**访问级别**度量，而不是"发现了几个漏洞"：

```
external < recon < web_user < web_admin < db_read < shell < root < domain_admin
```

一句话：**Finding 不是终点，立足点的推进才是。**

融合 6 个来源，经取舍而非堆砌：Cairn（状态空间搜索哲学）· Incalmo（高层攻击抽象）· XBOW（协调舰队 / 创造发现·确定裁决）· ARTEX（双图 / CAS / 串行链 / 冷图 / trace 协作）· Strix（沙箱执行器 / 知识包 / 报告）· BreachWeave（Observer 监督）。

## 它能到什么程度（里程碑 · 带 live 实证）

> 标 ✅ 的都有真实 run 的证据支撑（attack graph 里立足点/凭据 `verdict=verified`、Observer 零告警、报告每跳 PoC 可复现）；标 🚧 的主体已落地、仍在收尾。

**核心闭环（M0–M4）✅**
- **Web 真打**：Kali 沙箱里 GLM solver 自由 tool-use，自主打穿 OWASP Juice Shop（recon → SQLi 认证绕过 → UNION dump 全库 + 支付卡 + 破解哈希）。
- **内网横向**：从 Web 命令注入拿立足点 → 读凭据 → ssh 横向到内网主机拿 `shell@internal` + flag（靶场 `targets/lateral-lab`，live task `6df1fb958887`）。
- **规模化 + 结论可信**：Coordinator 按资产 fan-out 的并行 solver 舰队（CAS 领取、每 solver 独享沙箱、trace 协作）+ 全链路 MITM 留痕（报告每跳 `curl` 可复现）。

**打到访问模型顶点 `domain_admin` ✅**
- 真 Windows AD DC 上，单 solver 自主走完整链：member `/ping` 命令注入 → `root` → 读配置拿域凭据 → **Kerberoast** 服务账号 → `john` 破口令 → **DCSync** 抓域管 + `krbtgt` NT hash。两条 `domain_admin` 立足点 + 全部凭据 `verified`、Observer 零告警（live task `497336b6a14c`）。靶场见 [`targets/ad-lab`](./targets/ad-lab)。

**结论可信的地基：验"世界"不验"报告"（verifier）**
这是 Veritas 区别于"会自信胡说的 LLM agent"的核心。verdict 不看模型自己怎么描述战果，而是**由系统从已记录的真实世界（沙箱命令输出 / MITM 流量）按每个访问级别的"举证义务"重新推导**——调 prompt 把话说漂亮 ≠ 攻击真发生。三态 `verified` / `refuted` / `unproven`。
- **Stage 1 · 被动** ✅：从真实输出按义务自推导（如 `domain_admin` 必须有 DCSync 抓到 RID-500/krbtgt 的 hash 行，"够到 DC"这种弱证据不算）。
- **Stage 2 · 主动** ✅：引擎在判定前发**只有真拿下才能通过**的主动探针——自选随机 nonce 回环证 RCE、亲自重认证证凭据、重跑 DCSync 证域管；并能**证伪**伪造的口令 / 伪造的 RCE。
- **Stage 3 · 未知靶场证明模型** 🚧：声明式「举证义务注册表」+ 确定性 web 探针脊梁（ssti / sqli / lfi / open_redirect / ssrf / xxe / xss / idor / 认证类，经沙箱 curl / OOB canary / 进程内 Playwright 执行级验证）；写不出确定性义务的新类才降级到 **LLM-judge**（低信任档，**绝不**驱动 `verified`，Observer 交叉核）。

**工程化护栏（M5）**
- **安全闸** ✅：`scope` 授权边界真接入执行器与探针（越界命令直接拦、绝不执行）+ 分级自主 / 审批门（HITL，破坏性/大范围扫描/在线爆破默认 fail-closed）。碰真外部目标前的硬边界。
- **多 provider** ✅：GLM / DeepSeek / OpenAI / Anthropic 经 LiteLLM 一键切换，执行器零改动。
- **kill chain 可视化回放** ✅：每次 run 产出自包含单文件 HTML（攻击图泳道 + 动作回放 + 每跳证据/PoC），离线可开、可截图录屏。
- **跨 run 策略记忆** ✅：把【已验证】的成功 kill chain 蒸馏入库，新 run 遇相似目标检索复用（脱敏，只存通用动作、绝不存原始命令/凭据；提示永不驱动 verdict）。
- **冷图压缩** 🚧：转录超阈值时把中段旧 round-trip 确定性折成 digest，控长程 token 成本（零额外 LLM 开销）。

> **第一性目标 = HackerOne 这类授权外部目标**；本地靶场只是试验台。全自动打穿真实域控是能力边界，设计上为人机协同（HITL）留好接口，而非假装全自动。

## 架构（分层）

```
Operator(人) → Coordinator(协调/唯一规划) → Solver 舰队(fresh session · CAS 领取)
            → Executor(混合: 确定性动作 + 自由沙箱 Web Solver) → Attack Graph(双图黑板)
横切：知识包 / Kali 沙箱 / MITM 留痕 / verifier(被动+主动+义务表) / 安全闸 / 冷图压缩 / 策略记忆 / 多 provider
```

完整设计、抉择理由与路线图见 [PLAN.md](./PLAN.md)；项目权威上下文见 [CLAUDE.md](./CLAUDE.md)。

## 运行

```bash
# 依赖（已有 .venv 可复用）
python -m venv .venv && source .venv/bin/activate && pip install -e .
docker compose up -d postgres
cp dispatch.example.yaml dispatch.yaml

# mock（不烧钱，验推进闭环）
python -m veritas run --mock --target http://localhost:3000 --goal shell

# live（真打）：在 dispatch.yaml 配 target/goal/sandbox_network，设好 provider 的 API key
export GLM_API_KEY=...        # 或 DEEPSEEK_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY
python -m veritas run
```

- 查攻击图：连 Postgres `veritas` 库看 `footholds / credentials / loot / activity`（`activity` 有 solver 实际跑的命令）。
- 报告：`veritas_runs/<task>/killchain.md`（kill chain 树 + 每跳 PoC）与 `killchain.html`（可视化回放）。
- 靶场：内网横向 `targets/lateral-lab`；AD 域横向需云端真 Windows DC，见 [`targets/ad-lab/windows-dc/README.md`](./targets/ad-lab/windows-dc/README.md)。

## 文档

- [PLAN.md](./PLAN.md) — 完整设计蓝图（闭环判断、架构、抉择、路线图、M5 证明模型 Stage 1–3）
- [CLAUDE.md](./CLAUDE.md) — 项目权威上下文与分里程碑进展
- [docs/veritas-architecture.pdf](./docs/veritas-architecture.pdf) — 架构设计图
- `archive/v1-validator/` — v1（验证器方向，已弃）归档，保留演进史

## 许可

本项目采用 **AGPL-3.0** 授权（见 [LICENSE](./LICENSE)）：任何人可自由使用、修改、分发，但衍生作品（含通过网络提供的服务）须同样以 AGPL-3.0 开源。

## 免责声明

仅用于已获**合法书面授权**的渗透测试、安全研究与本地靶场验证。内置 `scope` 授权边界与分级审批门用于防止越界，但使用者须自行确保行为符合所在地法律法规，一切后果由使用者承担。
