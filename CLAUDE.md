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
- **下一步候选**：多"根目标"并行(当前单任务内多资产 fan-out) · 真 SOCKS pivot · AD 域靶场 · M5(冷图压缩/跨 run 策略记忆/审批门) · build-in-public 素材(M4 live 报告现成)

## 代码结构
```
veritas/core/     board(攻击图) · coordinator(分解多前沿) · solver(CAS领取+apply判verdict) · verifier(证据判定·防幻觉) · observer(旁路监督) · state(访问模型) · engine(推进循环)
veritas/executors/ mock(M0桩,多主机) · web_solver(GLM 自由沙箱挖洞+横向; trace/repeat_request)
veritas/runtime/  sandbox(Kali 容器 shell) · mitm(记录型代理·全链路HTTP留痕+CA注入)
veritas/llm/      client(GLM-5.3 via litellm)
veritas/knowledge/ skills/*.md(web-recon/sqli/auth/lateral) + loader
veritas/report/   killchain(kill chain 树 + 每跳 PoC + 舰队归属 + MITM curl 复现 + 结论可信度)
schema.sql(双图 + footholds/credentials.verdict + http_flows) · dispatch.yaml(本地,gitignore) · containers/Dockerfile(Kali沙箱,含mitmproxy) · targets/lateral-lab/(横向靶场)
```

## 技术栈 & 环境
Python 3.12 + asyncpg + PostgreSQL(docker compose) + litellm + playwright。沙箱镜像 `veritas-sandbox:latest`(kali-linux-default 全家桶)。LLM = GLM-5.3(litellm openai 兼容端点 + `GLM_API_KEY` 环境变量)。

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
