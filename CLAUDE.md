# Veritas — 自动化渗透引擎 · 项目上下文

> 给在此工作区协作的 Claude：这是权威上下文，先读这份。完整设计见 [PLAN.md](./PLAN.md)，架构图 [docs/veritas-architecture.pdf](./docs/veritas-architecture.pdf)。

## 定位
真正的**自动化渗透引擎**——能挖 HackerOne、能从 Web 打进内网横向。**不是**漏洞扫描器 / BAS 验证器（v1 验证器方向已废弃，归档在 `archive/v1-validator/`）。

## 核心抽象
渗透 = **攻击图上的状态空间搜索**：节点 = 立足点 / 资产 / 凭据 / 战利品，边 = kill-chain 动作（利用漏洞→权限跃迁）。进展用访问级别度量：
`external < recon < web_user < web_admin < db_read < shell < root < domain_admin`
一句话：**Finding 不是终点，立足点的推进才是。**

## 架构（分层，详见 PLAN.md §三）
`Operator(人) → Coordinator(协调/唯一规划) → Solver 舰队(fresh session, CAS 领取) → Executor(混合: 确定性动作 + 自由沙箱 Web Solver) → Attack Graph(双图黑板)`。横切：知识包 / Kali 沙箱 / MITM 留痕 / 冷图压缩 / 审批门 / 多 provider。
设计血缘：Cairn(状态空间搜索) + Incalmo(高层攻击抽象) + XBOW(舰队 / creative·deterministic) + ARTEX(双图/CAS/trace/冷图) + Strix(沙箱执行器/知识包/报告) + BreachWeave(Observer)。参考项目源码在全量工作目录 `../`（Cairn/strix/ARTEX/BreachWeave），关键文件路径见 PLAN.md 末尾。

## 进展（核心能力已全通）
- **M0** 攻击图推进骨架(双图/CAS/mock kill chain) ✅
- **M1** 单机 Web 真打(Kali 沙箱 + GLM-5.3 Web Solver 自由 tool-use) ✅ — 自主打穿 Juice Shop：recon→SQLi 认证绕过→UNION dump 全库+支付卡+破解哈希
- **M2** 利用链 — GLM 单 solver 自发完成（未单独实现）✅
- **M3** 内网横向(靶场 `targets/lateral-lab`) ✅ — GLM 自主发现命令注入→**自封装 pivot helper `c()`**→读凭据→ssh 横向→`shell@internal` + flag。kill chain: external→shell→root
- **M4** 规模化+结论可信 ✅ **三刀落地 + live 整链通过** — ① 舰队真并行(Coordinator 按资产分解 fan-out + CAS + 每 solver 独享按需沙箱 + 难点重试封顶) + trace 协作(`search_worker_traces`)；② 证据确定性验证层(`verifier` 判 verdict，`max_access` 只认 verified·防幻觉) + Observer 监督(`observer` 失速/鬼打墙/早停·误报)；③ 全链路 MITM 留痕(`runtime/mitm` 沙箱内 mitmdump+CA 注入→`http_flows`，报告每跳 curl 可复现) + `repeat_request`。kill-chain 树按访问级别串 pivot 父子链(还原 edge→internal)。**live 实证**(task `6df1fb958887`)：GLM 单 solver 打穿 lateral-lab→拿内网 shell+flag，立足点/凭据全 verified、Observer 零告警、MITM 54 条真流量入库可 curl 复现。
- **AD 域横向**(靶场 `targets/ad-lab`，云 x64 Windows Server DC) ✅ — GLM 单 solver 自主打到访问模型顶点 **domain_admin**：member `/ping` 命令注入→root→读 config.ini 拿域凭据 webdev→Kerberoast svc-sql→john 破 `Password1`→DCSync 抓 RID-500(`labadmin`)+`krbtgt` NT hash。两条 domain_admin 立足点+全部凭据 verified、Observer 零告警(live task `497336b6a14c`)。**踩坑**：Samba AD DC 与 impacket 的 Kerberos(AES256 会话密钥报 `INAPP_CKSUM`)+DRSUAPI DCSync 根本不兼容(MIT 客户端却正常)，换**真 Windows Server** 才通(Azure 云 DC)；Azure 新林首台 DC 的 RID-500 内置域管叫 `labadmin` 非 `Administrator`。
- **verifier 升级：验"世界"不验"报告"(Stage 1)** ✅ — verdict 由系统从真实输出按每级**举证义务**自推导(domain_admin=DCSync RID-500/krbtgt 行，且不接受"够到 DC"这种弱证据；root=`uid=0`；location 抽裸主机/IP 对 rc=0 命令)，三态 `verified`/`refuted`/`unproven`。修掉旧版"匹配 solver 自述 evidence 串"易过拟合模型措辞的问题(调 prompt 就能变绿≠攻击真发生)。设计/Stage2-3 见 PLAN.md M5。
- **verifier 升级：主动探世界(Stage 2)** ✅ — 新增持沙箱的 `core/prober.py`：在 verifier 判定前，执行器对刚上报的战果发**只有真拿下才能通过**的主动探针——① **nonce 回环**(shell/root：引擎自选随机 nonce 经立足点向量回显 + 同响应 `uid=0`，**按主机限定**修 Stage1 松点)；② **重认证**(credential：引擎亲跑 `nxc` 认证，`[+]`→proven/`[-]`→refuted，不信自述)；③ **重跑 DCSync**(domain_admin：授权靶场认 RID-500/krbtgt)。verifier 纯函数接收 `ProbeResult` 当数据、**主动优先于被动**(proven→verified/refuted→refuted/inconclusive→回落)。`report_foothold` 加 `replay` 字段(可重放 PoC：`command_template` 含 `{CMD}` / `verify_command`)。**safe-probe 策略(一等公民)**：low(nonce)/medium(重认证)/high(DCSync)+预算；`external`(默认)只放 low，medium/high 降级被动 proof-of-effect+PoC+LLM-judge(低信任档·不驱动 verdict)；`lab` 开各级。**第一性=HackerOne 外部目标，靶场只试验台**。验证：21 确定性单测 + **live 回归 7/7**(真沙箱+真云 DC，复用金数据 `497336b6a14c`)——nonce 证 member RCE、重认证证 svc-sql、重 DCSync 证 domain_admin、**证伪**伪造口令/伪造 RCE、外部策略 low 探 medium 降级。设计见 PLAN.md M5 Stage 2。
- **verifier 升级：未知靶场证明模型(Stage 3)** 🚧 — **第一刀**：`core/obligations.py` **举证义务注册表**：把 Stage1/2 硬编码义务(shell/root/domain_admin)迁成声明式 `ObligationSpec`，verifier proof-of-effect 改**查表**(单一真源)；`has_deterministic()` 做"有无确定性义务"岔路。**LLM-judge 闭环**：无确定性义务的类→ executor 收可复现 PoC(replay+MITM)→ `prober.llm_judge` 评级 → `props.probe_judge`(标 `llm-judged` 低信任)；**verdict 永远确定性路决定、LLM-judge 绝不驱动 verified**；Observer 交叉核 flag "仅 llm-judged 支撑"。真 GLM 确认 OK(真漏洞判 unclear·噪声判 contradicts·都不驱动)。**Cut 2a**：确定性脊梁扩到 web 漏洞面——注册表+prober 加 4 类确定性 web 探针(经沙箱 curl→MITM，引擎自选标记/挑战经注入点回环)：**ssti**(两数之积=真求值/字面回显=反证)、**sqli**(借v1三oracle 报错/认证绕过/布尔 + union 带回 nonce)、**lfi**(/etc/passwd root:0:0 结构)、**open_redirect**(3xx Location=引擎URL=真控/指向自身=反证)。纪律：回显不算证据、验不出 unproven。sqli/ssti/lfi 跟随重定向取末段、open_redirect 不跟随。`replay` 扩 web 字段。**Cut 2b**：OOB canary 子系统(`runtime/oob_listener.py` 自托管 HTTP 监听 + `HttpOOB`) + `_probe_ssrf`/`_probe_xxe`(注入引擎 canary→poll 命中=proven，未配/未命中 inconclusive)；config `probe.oob_url`。**Cut 2c**：`_probe_xss`(引擎进程内 Playwright 执行级，token 弹窗/DOM，非回显) + `_probe_authn`(web_user/web_admin 带会话 vs 匿名基线差分)；db_read 由 sqli 覆盖。**Cut 2d**：`_probe_idor`(用自己会话读他人对象的唯一标记=越权确证)。**确定性脊梁已覆盖** rce/ssti/sqli/lfi/open_redirect/ssrf/xxe/xss/web_user/web_admin/idor；业务逻辑/竞态等才留 LLM-judge。验证：prober 单测 **49/49** + 各刀 live 全绿(2a 9/9·2b OOB 4/4·2c 4/4·2d 2/2，真沙箱 curl / host Playwright / 真 OOB 监听 / 真漏洞靶)。详见 PLAN.md M5 Stage 3。
- **M5 冷图压缩(转录压缩·控长程成本)** 🚧 — `llm/compaction.py`(纯函数)：web_solver 的 agentic loop 每步 llm.chat 前调 `compact_messages`，转录超阈值(≈50K tokens)就把中段旧 round-trip 折成**确定性 digest**(每 tool_call 压成"命令→输出尾"一行 + 指向 search_worker_traces)，保留 system+初始任务+最近 N 轮热前沿。**零额外 LLM 成本**(确定性滚动)；攻击图状态在 DB 不受影响，细节可检索恢复。按完整 round-trip 折叠、保 tool_call 配对合法。借 ARTEX coldgraph 原则(折冷/留热前沿/去抖低水位)但作用在转录(veritas LLM 只看转录非图总览)。验证：17 单测(no-op/折叠有界/结构合法/保前沿/digest 滚动/再压缩合并/60步循环有界 peak<1.5×阈值) + prober 49 零回归。后续：checkpoint 断点续跑 / 阈值 config 化 / LLM 摘要式 digest(可选)。详见 PLAN.md M5。
- **M5 安全闸（分级自主/审批门 + scope 真接入 executor·碰真外部目标前的硬边界）** ✅ — 新建 `veritas/safety/` 包。**① scope 真接入**（堵明确安全漏洞：engine 旧版 `build_registry` 没传 scope→守卫永不触发，`ScopeCfg` 也没 `allows_cmd`；实测 task `6661273c36a0` GLM 被域凭据勾引往关机云 DC + Docker 网关撞十几次没人拦）：`safety/scope.py` 纯函数从命令抽【连接目标】主机/IP（所有 IP 字面量一律抽=高信号堵越界；URL 只取 authority、query 内嵌 URL 与 `--data`/`-H` 旗标值里的 FQDN 不抽=不误杀开放重定向类合法请求），比对 domains+CIDR：域内放行/域外拒绝/本地命令放行/单标签内网名放行(不误杀横向)/多标签外部 FQDN 拒绝/loopback 恒放行/空 scope 不强制。engine 把 `cfg.scope` 一路传进 web_solver（越界回提示给 LLM + 落 `activity(gate=scope_denied)`）**和 prober**（nonce/重认证/DCSync/9 类 web 探针目标向量越界→降级 INCONCLUSIVE 绝不 refuted；例外 `_oob_poll` 查引擎自托管监听器非目标）。**② 分级自主/审批门(HITL)**：`safety/autonomy.py` `classify` 按破坏性/噪声分 benign/file_write/file_delete/destructive/broad_scan/bruteforce（噪声档 low/medium/high 与 prober safe-probe 对齐复用）；`AutonomyPolicy.mode=auto` 按 `probe.authorization` 推导(lab→full_auto / external→approval)；无人在环时 approval 下 `on_gated=deny`(**fail-closed 默认**)拦破坏性/大范围扫描/在线爆破(回提示换招+落 `gate=needs_approval`+Observer 交叉核)，`on_gated=allow` 给受监督 run 的 fail-open 选项。纪律：sandbox scratch 写/窄扫描/单文件 rm/读命令不误杀。报告加「安全闸」小节。真正的交互式暂停/恢复 UI 留后续。**验证**：`tests/safety/` 三套确定性单测全绿(test_scope 36 例·test_autonomy·test_wiring 18 例 async 假 sandbox 不调 GLM，证越界命令被拦且沙箱从未被调用、合法横向不误杀、破坏性按策略放/拦)；prober 对 scope=None 零行为变化。live 复验 GLM 越界被拦待用户终端跑。详见 PLAN.md M5。
- **M5 kill chain 可视化回放(build-in-public)** ✅ — `report/killchain_viz.py`：`build_payload`(纯函数)把攻击图+战果+命令时间线整理成 payload（按访问级别排 rank·pivot 边只留立足点间·activity 分类成回放时间线·凭据脱敏·统计 verified/refuted/unproven+安全闸事件），`export_html` 注内联模板出**自包含单文件**(内联 CSS/JS+SVG·无外部依赖·离线可开·可截图录屏)。查看器：访问级别泳道+verdict 配色+pivot 边+▶回放(按 created_at 点亮节点)+点节点看证据/探针/PoC+侧栏 tab(凭据/战利品/漏洞/MITM curl/安全闸)+明暗主题。接进 `killchain.generate` 每次 run 顺带产出 `killchain.html`。验证：30 单测 + 两次真 run 实载(2f8d0af3ad72/960ed37db50e·零 console error)，且第一天就靠「安全闸」tab 揪出 scope 单标签回归并修掉。详见 PLAN.md M5。
- **M5 跨 run 策略记忆(cross-run strategy memory·v1)** ✅ — 让引擎"越打越聪明"：把【已验证】成功 kill chain 蒸馏成策略存库，新 run 遇相似目标检索复用为提示。`core/memory.py` `distill_strategy`(纯·只收 verified 且 rank>external)/`fingerprint_tags`/`relevance`；`schema.sql` 加 `strategies` 表(tags TEXT[] GIN + steps JSONB)；`board.add_strategy`/`search_strategies`(标签重叠 或 ILIKE·Python 按重叠度排序)；`web_solver` 启动按指纹注入历史策略提示 + 工具 `recall_strategy(query)`(镜像 search_worker_traces)；`engine.run` 结束(live+verified 进展)蒸馏入库。**两条铁律**：① 脱敏——approach 只存通用动作描述(web/ssti·命令执行回环·DCSync)**绝不存原始命令/凭据**(AD verify_command 带域口令，单测塞假口令验不外泄)；② 提示永不驱动 verdict(verifier/prober 仍从真实输出重推)。config `memory`(enabled/max_hints·A/B 复现设 false)。v1 轻量确定性(不上向量库)。验证：23 确定性单测 + 9 真 Postgres 临时库集成测(add/search 往返·标签重叠·ILIKE·exclude·脱敏持久化)。详见 PLAN.md M5。
- **M5 多 provider(GLM/DeepSeek/OpenAI/Anthropic 一键切换)** ✅ — M5 完成定义最后一项收官。LLM 层本就走 LiteLLM(天然多 provider)，补的是`llm/providers.py` 预设表(glm 智谱兼容端点/deepseek 原生/openai 别名 gpt/anthropic 别名 claude，各补全 model 路由+api_base+key 环境变量)+ `resolve()` 纯函数(显式 llm.model/api_base/api_key_env 覆盖预设，不填 provider→纯显式字段向后兼容)；`LLMCfg` 加 provider 字段(默认 glm，model 默认空=用预设)，`LLMClient` 经 resolve 接线+key 缺失告警。**关键**：LiteLLM 统一各家 tool-use+响应格式，切 provider 时 executor/web_solver/prober **零改动**。key 走环境变量(GLM_API_KEY/DEEPSEEK_API_KEY/OPENAI_API_KEY/ANTHROPIC_API_KEY)。验证：25 单测(resolve 预设/别名/覆盖/未知/向后兼容 + client 接线)+全套回归零破坏。各家 model id 随版本漂移→预设给起步建议、llm.model 覆盖。详见 PLAN.md M5。
- **下一步候选**：M5 其余支柱(冷图压缩 checkpoint) · 安全闸 live 复验(scope 已 live 坐实 3→0·交互式审批 UI 待做) · 策略记忆 live 验(连跑两次命中历史策略)+embedding 检索 · Stage 3 收尾(DNS-OOB·真 interactsh / 盲注时间 oracle / 沙箱补 chromium) · 多"根目标"并行 · 真 SOCKS pivot · build-in-public 素材(M3/M4/AD/Stage2/Stage3/冷图/安全闸/可视化/策略记忆 现成)

## 代码结构
```
veritas/core/     board(攻击图) · coordinator(分解多前沿) · solver(CAS领取+apply判verdict) · verifier(证据判定·防幻觉·Stage1被动+Stage2主动+Stage3查义务表) · prober(主动探针·持沙箱·safe-probe策略·受scope约束) · obligations(举证义务注册表·Stage3) · observer(旁路监督+llm-judged+needs_approval交叉核) · memory(跨run策略记忆·distill/fingerprint/capture·纯+脱敏) · state(访问模型) · engine(推进循环·串scope+autonomy+memory)
veritas/executors/ mock(M0桩,多主机) · web_solver(GLM 自由沙箱挖洞+横向; trace/repeat_request/recall_strategy; _safety_gate执行点=scope+审批门; 启动注入跨run策略提示)
veritas/safety/   scope(授权边界·抽连接目标比对domains+CIDR·纯函数) · autonomy(分级自主/审批门HITL·classify破坏性+AutonomyPolicy·与safe-probe对齐)
veritas/runtime/  sandbox(Kali 容器 shell) · mitm(记录型代理·全链路HTTP留痕+CA注入)
veritas/llm/      client(LiteLLM·多provider·成本累计) · providers(GLM/DeepSeek/OpenAI/Anthropic 预设+resolve·纯函数) · compaction(冷图压缩·转录压缩·控长程成本·纯函数)
veritas/knowledge/ skills/*.md(web-recon/sqli/auth/lateral) + loader
veritas/report/   killchain(kill chain 树 + 每跳 PoC + 舰队归属 + MITM curl 复现 + 安全闸小节 + 结论可信度) · killchain_viz(可视化回放·自包含单文件 HTML·build_payload纯函数+export_html)
tests/            safety/(scope/autonomy/wiring) · report/(killchain_viz) · memory/(memory+真DB集成) · llm/(providers) 确定性单测(纯 .venv/bin/python·无 pytest 依赖)
schema.sql(双图 + footholds/credentials.verdict + http_flows) · dispatch.yaml(本地,gitignore) · containers/Dockerfile(Kali沙箱,含mitmproxy) · targets/lateral-lab/(横向靶场)
```

## 技术栈 & 环境
Python 3.12 + asyncpg + PostgreSQL(docker compose) + litellm + playwright。沙箱镜像 `veritas-sandbox:latest`(kali-linux-default 全家桶)。LLM = **多 provider via LiteLLM**(GLM/DeepSeek/OpenAI/Anthropic 一键切换，见 `llm/providers.py`；默认 GLM-5.3 智谱兼容端点 + `GLM_API_KEY`，各家 key 走对应环境变量)。

## 怎么跑
```bash
# 依赖（已有 .venv 可复用）
python -m venv .venv && source .venv/bin/activate && pip install -e .
docker compose up -d postgres
cp dispatch.example.yaml dispatch.yaml

# mock（不烧钱，验推进闭环）
python -m veritas run --mock --target http://localhost:3000 --goal shell

# M1 live（打 Juice Shop）：dispatch target=http://localhost:3000, sandbox_network=host
export GLM_API_KEY=...; python -m veritas run

# M3 live（内网横向）：先起靶场，dispatch target=http://lab-edge:8080, sandbox_network=lateral-lab_frontend
docker compose -f targets/lateral-lab/docker-compose.yml up -d --build
python -m veritas run
```
查攻击图：连 postgres `veritas` 库看 `footholds / credentials / loot / activity`（activity 有 GLM 实际命令）。

## 协作约定（重要）
- **Claude 写代码 + 本地 `git commit`；用户在自己终端 `git push`**。Claude 的 shell 在沙箱里、出站受限（GitHub SSH 22 被拦、读不到钥匙串 token），所以**需联网/认证的操作（push、`docker build` 拉包）都由用户终端做**；remote 用 HTTPS。
- 小步 commit，自测/live 验证通过再 commit；commit message 用中文、按 `feat(mX)/fix/docs` 前缀。
- **默认简体中文回复。**

## 已知坑
- litellm 算不出 `glm-5.3` 单价 → 成本显示 `$0`（**非未调用**，实际费用见智谱后台；已改为显示 token 用量）。
- postgres 若残留 v1 表会与 v2 schema 冲突 → `docker compose down -v` 重置。
- macOS Docker Desktop：sandbox `--network host` 下 `localhost` 能通到映射到 host 的容器(Juice Shop)；横向走靶场 `frontend` 网。
- 自测用临时库（`VERITAS_DSN` 指向新建库）避免碰正式数据；脚本别命名 `inspect.py`（撞标准库）。
