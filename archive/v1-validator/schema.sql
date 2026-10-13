-- Veritas schema — 幂等建表（启动即迁移，"重启即迁移"）
-- 对应 PHASE0.md §3

-- 资产真值图（Phase 0 按 task 隔离；Phase 2 做全局合并）
CREATE TABLE IF NOT EXISTS assets (
  id          BIGSERIAL PRIMARY KEY,
  task_id     TEXT NOT NULL,
  type        TEXT NOT NULL,                 -- root_domain/subdomain/ip/service/endpoint
  parent_id   BIGINT REFERENCES assets(id),
  dedup_key   TEXT NOT NULL,                 -- 程序计算，去重用
  score       REAL DEFAULT 0,               -- 攻击面打分（Phase1 用，先留列）
  tested      BOOLEAN DEFAULT FALSE,
  in_scope    BOOLEAN DEFAULT TRUE,
  props       JSONB DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT now(),
  UNIQUE (task_id, dedup_key)
);

-- 探索血缘图：节点
CREATE TABLE IF NOT EXISTS nodes (
  id          BIGSERIAL PRIMARY KEY,
  task_id     TEXT NOT NULL,
  kind        TEXT NOT NULL,                 -- goal/intent/observation/fact/finding/hint/strategy
  state       TEXT NOT NULL DEFAULT 'open',  -- intent:open/claimed/done ; finding:candidate/confirmed/refuted/insufficient
  payload     JSONB NOT NULL,
  provenance  JSONB DEFAULT '{}',            -- {source_tool,request,ts,untrusted}
  claimed_by  TEXT,
  claimed_at  TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_nodes_claim ON nodes(task_id, kind, state);

-- 探索血缘图：边
CREATE TABLE IF NOT EXISTS edges (
  src  BIGINT NOT NULL,
  dst  BIGINT NOT NULL,
  rel  TEXT NOT NULL,                        -- spawns/yields/derived_from/proves
  PRIMARY KEY (src, dst, rel)
);

-- 锚点：探索节点 ↔ 资产
CREATE TABLE IF NOT EXISTS anchors (
  node_id  BIGINT NOT NULL,
  asset_id BIGINT NOT NULL,
  PRIMARY KEY (node_id, asset_id)
);

-- 执行过程库（trace，供过程级检索）
CREATE TABLE IF NOT EXISTS activity (
  id         BIGSERIAL PRIMARY KEY,
  task_id    TEXT,
  intent_id  BIGINT,
  worker_id  TEXT,
  step       INT,
  content    JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 事件（驱动引擎）
CREATE TABLE IF NOT EXISTS events (
  id         BIGSERIAL PRIMARY KEY,
  task_id    TEXT,
  type       TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 任务
CREATE TABLE IF NOT EXISTS tasks (
  id         TEXT PRIMARY KEY,
  target     TEXT NOT NULL,
  state      TEXT NOT NULL DEFAULT 'running', -- running/done/failed
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
