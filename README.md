# Veritas

> 自动化渗透引擎 —— 在**攻击图**上做访问权限推进，能挖 HackerOne，能从 Web 打进内网横向。

渗透被建模成「攻击图」上的状态空间搜索：节点是立足点 / 资产 / 凭据 / 战利品，边是 kill-chain 动作（利用漏洞 → 权限跃迁），目标是达成某个访问级别或拿到某份数据。进展用**访问级别**度量（`external → … → shell → domain_admin`），而不是"发现了几个漏洞"。

融合 6 个来源，经取舍而非堆砌：Cairn（状态空间搜索哲学）· Incalmo（高层攻击抽象）· XBOW（协调舰队 / 创造发现·确定裁决）· ARTEX（双图 / CAS / 串行链 / 冷图 / trace 协作）· Strix（沙箱执行器 / 知识包 / 报告）· BreachWeave（Observer 监督）。

## 文档

- [PLAN.md](./PLAN.md) — 完整设计蓝图（闭环判断、架构、抉择、路线图）
- [docs/veritas-architecture.pdf](./docs/veritas-architecture.pdf) — 架构设计图（可视化）
- `archive/v1-validator/` — v1（验证器方向，已弃）归档，保留演进史

## 状态

- ✅ 架构设计完成
- 🔜 **M0 · 骨架能推进**：攻击图 + Coordinator + Solver + Executor 接口 + mock 演示完整 kill chain

路线：`M0 骨架能推进` → `M1 单机 Web 真打` → `M2 Web 利用链闭环` → `M3 多主机横向闭环` → `M4 规模化+结论可信` → `M5 长程+工程化`

## 开发

```bash
# 依赖（已有 .venv 可复用）
python -m venv .venv && source .venv/bin/activate
pip install -e .
# 数据库
docker compose up -d postgres
```

## 许可

本项目采用 **AGPL-3.0** 授权（见 [LICENSE](./LICENSE)）：任何人可自由使用、修改、分发，但衍生作品（含通过网络提供的服务）须同样以 AGPL-3.0 开源。

## 免责声明

仅用于已获**合法书面授权**的渗透测试、安全研究与本地靶场验证。使用者须自行确保行为符合所在地法律法规，一切后果由使用者承担。
