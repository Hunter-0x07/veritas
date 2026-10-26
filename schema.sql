-- Veritas v2 schema — 攻击图上的访问权限推进。幂等建表（启动即迁移）。

CREATE TABLE IF NOT EXISTS tasks (
  id         TEXT PRIMARY KEY,
  target     TEXT NOT NULL,
  goal       TEXT NOT NULL DEFAULT 'shell',   -- 目标访问级别
  state      TEXT NOT NULL DEFAULT 'running',  -- running/reached/exhausted/failed
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- 立足点：状态空间的节点，渗透进展的度量
CREATE TABLE IF NOT EXISTS footholds (
  id           BIGSERIAL PRIMARY KEY,
  task_id      TEXT NOT NULL,
  label        TEXT NOT NULL,              -- 人读标签，如 shell@10.0.0.5
  access_level TEXT NOT NULL,              -- external/recon/web_user/web_admin/db_read/shell/root/domain_admin
  location     TEXT,                       -- 立足点所在：URL/主机/服务
  verdict      TEXT NOT NULL DEFAULT 'verified', -- 证据判定：verified/unproven/refuted（防幻觉，只 verified 计入进展）
  props        JSONB DEFAULT '{}',
  created_at   TIMESTAMPTZ DEFAULT now(),
  UNIQUE (task_id, label)
);

-- 资产真值图（去重交给唯一索引 + ON CONFLICT）
CREATE TABLE IF NOT EXISTS assets (
  id             BIGSERIAL PRIMARY KEY,
  task_id        TEXT NOT NULL,
  type           TEXT NOT NULL,            -- webapp/host/service/endpoint
  dedup_key      TEXT NOT NULL,
  reachable_from BIGINT,                   -- 从哪个 foothold 够得到（内网资产）
  tested         BOOLEAN DEFAULT FALSE,
  in_scope       BOOLEAN DEFAULT TRUE,
  props          JSONB DEFAULT '{}',
  created_at     TIMESTAMPTZ DEFAULT now(),
  UNIQUE (task_id, dedup_key)
);

-- 攻击机会（意图）：从某立足点对某资产的一步
CREATE TABLE IF NOT EXISTS opportunities (
  id            BIGSERIAL PRIMARY KEY,
  task_id       TEXT NOT NULL,
  kind          TEXT NOT NULL,             -- initial_access/web_exploit/internal_recon/lateral_move/privesc/loot
  from_foothold BIGINT,
  target_asset  BIGINT,
  state         TEXT NOT NULL DEFAULT 'open', -- open/claimed/done/failed
  payload       JSONB DEFAULT '{}',        -- {ev, goal_access, ...}
  claimed_by    TEXT,
  claimed_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_opp_claim ON opportunities(task_id, state);

-- 漏洞证据：确认"这条边能走"（不是终点）
CREATE TABLE IF NOT EXISTS findings (
  id           BIGSERIAL PRIMARY KEY,
  task_id      TEXT NOT NULL,
  type         TEXT NOT NULL,              -- sqli/xss/idor/ssrf/rce/auth/...
  foothold_id  BIGINT,
  asset_id     BIGINT,
  severity     TEXT,
  evidence     JSONB DEFAULT '{}',
  reproduction TEXT,
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- 凭据战利品：推进与横向的燃料
CREATE TABLE IF NOT EXISTS credentials (
  id         BIGSERIAL PRIMARY KEY,
  task_id    TEXT NOT NULL,
  kind       TEXT NOT NULL,                -- password/hash/token/key
  username   TEXT,
  secret     TEXT,
  source     TEXT,
  verdict    TEXT NOT NULL DEFAULT 'verified', -- 证据判定：verified/unproven/refuted
  props      JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE (task_id, kind, username, secret)
);

-- 数据战利品
CREATE TABLE IF NOT EXISTS loot (
  id         BIGSERIAL PRIMARY KEY,
  task_id    TEXT NOT NULL,
  kind       TEXT NOT NULL,                -- data/flag/source/file
  summary    TEXT,
  props      JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- kill chain 血缘边
CREATE TABLE IF NOT EXISTS edges (
  src  BIGINT NOT NULL,
  dst  BIGINT NOT NULL,
  rel  TEXT NOT NULL,                      -- spawns/exploits/yields/proves/derived_from/pivots_to
  kind TEXT,                               -- 两端节点类型，便于回放
  PRIMARY KEY (src, dst, rel)
);

CREATE TABLE IF NOT EXISTS activity (
  id             BIGSERIAL PRIMARY KEY,
  task_id        TEXT, opportunity_id BIGINT, worker_id TEXT,
  step           INT, content JSONB, created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY, task_id TEXT, type TEXT, created_at TIMESTAMPTZ DEFAULT now()
);

-- 全链路 MITM 留痕：记录型代理抓到的每条 HTTP 请求/响应（每跳 PoC 的原始可复现证据）
CREATE TABLE IF NOT EXISTS http_flows (
  id           BIGSERIAL PRIMARY KEY,
  task_id      TEXT NOT NULL,
  worker_id    TEXT,
  method       TEXT,
  url          TEXT,
  host         TEXT,
  status       INT,
  req_headers  JSONB DEFAULT '{}',
  req_body     TEXT,
  resp_headers JSONB DEFAULT '{}',
  resp_body    TEXT,
  ts           DOUBLE PRECISION,           -- 请求开始时间（排序/对齐 activity）
  created_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_flow_task ON http_flows(task_id, id);

-- 跨 run 策略记忆（M5）：把【已验证】成功 kill chain 蒸馏成策略存库，新 run 检索复用为提示。
-- 纪律：只存【动作/漏洞路径/技能】，绝不存跨 run 的凭据/secret/loot 值（脱敏，见 core/memory.py）。
CREATE TABLE IF NOT EXISTS strategies (
  id         BIGSERIAL PRIMARY KEY,
  task_id    TEXT,
  target     TEXT,
  tags       TEXT[] DEFAULT '{}',          -- 指纹标签（vuln类型/服务/app签名/访问路径），检索主键
  summary    TEXT,                         -- 一句话策略摘要（人读 + 注入提示用）
  steps      JSONB DEFAULT '[]',           -- 有序策略步骤（脱敏：access_level + vuln_type + approach）
  max_access TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_strategies_tags ON strategies USING GIN(tags);

-- 旧库迁移：补 verdict 列（幂等，建表在前故放末尾）
ALTER TABLE footholds   ADD COLUMN IF NOT EXISTS verdict TEXT NOT NULL DEFAULT 'verified';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS verdict TEXT NOT NULL DEFAULT 'verified';
