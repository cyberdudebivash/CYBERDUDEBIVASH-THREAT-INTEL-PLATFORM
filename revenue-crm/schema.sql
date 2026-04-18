-- =============================================================================
-- CYBERDUDEBIVASH® SENTINEL APEX — Revenue CRM Schema v123.0.0
-- Cloudflare D1 (SQLite) — deploy via: npx wrangler d1 execute sentinel-crm --file=schema.sql
-- =============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ─── LEADS ────────────────────────────────────────────────────────────────────
-- All captured leads from website, API gates, trial requests, cold inbound
CREATE TABLE IF NOT EXISTS leads (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  company         TEXT DEFAULT '',
  role            TEXT DEFAULT '',
  context         TEXT DEFAULT 'generic',   -- ioc_access | stix_request | demo | trial | subscribe
  source          TEXT DEFAULT 'web',       -- web | api | outbound | referral | manual
  status          TEXT DEFAULT 'new',       -- new | contacted | demo_scheduled | trial | customer | churned
  score           INTEGER DEFAULT 30,       -- 0–100 lead quality score
  captured_at     TEXT NOT NULL,
  last_activity   TEXT NOT NULL,
  country         TEXT DEFAULT '',
  ip_hash         TEXT DEFAULT '',
  tags            TEXT DEFAULT '[]',        -- JSON array: ["finance","c-suite","siem-user"]
  notes           TEXT DEFAULT '',
  linkedin        TEXT DEFAULT '',
  sequence_step   INTEGER DEFAULT 0,
  sequence_name   TEXT DEFAULT '',
  trial_activated INTEGER DEFAULT 0,        -- 1 = trial started
  converted       INTEGER DEFAULT 0,        -- 1 = paid customer
  converted_plan  TEXT DEFAULT '',          -- pro | enterprise
  converted_at    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_leads_status   ON leads(status);
CREATE INDEX IF NOT EXISTS idx_leads_score    ON leads(score DESC);
CREATE INDEX IF NOT EXISTS idx_leads_captured ON leads(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_leads_country  ON leads(country);

-- ─── DEALS ────────────────────────────────────────────────────────────────────
-- Enterprise + Pro deal pipeline with stage tracking and weighted ARR
CREATE TABLE IF NOT EXISTS deals (
  id                  TEXT PRIMARY KEY,
  lead_email          TEXT NOT NULL,
  company             TEXT NOT NULL,
  deal_name           TEXT NOT NULL,
  stage               TEXT DEFAULT 'new',  -- new|contacted|demo_scheduled|demo_done|trial|negotiation|closed_won|closed_lost
  plan                TEXT DEFAULT 'enterprise',  -- pro | enterprise | enterprise_custom
  value_inr           INTEGER DEFAULT 14999,      -- monthly value INR
  value_usd           INTEGER DEFAULT 199,        -- monthly value USD
  annual_value_inr    INTEGER DEFAULT 0,          -- 0 = monthly, >0 = annual
  close_probability   REAL DEFAULT 0.10,          -- 0.0–1.0
  expected_close      TEXT DEFAULT '',            -- YYYY-MM-DD
  weighted_value_inr  INTEGER DEFAULT 0,          -- value_inr * close_probability
  source              TEXT DEFAULT 'inbound',     -- inbound | outbound | referral | demo_request
  notes               TEXT DEFAULT '',
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL,
  owner               TEXT DEFAULT 'sales@cyberdudebivash.com',
  deal_slack_notified INTEGER DEFAULT 0,
  contract_ref        TEXT DEFAULT '',
  closed_at           TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_deals_stage      ON deals(stage);
CREATE INDEX IF NOT EXISTS idx_deals_company    ON deals(company);
CREATE INDEX IF NOT EXISTS idx_deals_email      ON deals(lead_email);
CREATE INDEX IF NOT EXISTS idx_deals_created    ON deals(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deals_value      ON deals(value_inr DESC);

-- ─── OUTREACH LOG ─────────────────────────────────────────────────────────────
-- Every email sent, scheduled, bounced, opened, replied
CREATE TABLE IF NOT EXISTS outreach_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  lead_email      TEXT NOT NULL,
  template        TEXT NOT NULL,
  sequence_name   TEXT DEFAULT '',
  sequence_step   INTEGER DEFAULT 0,
  scheduled_at    TEXT NOT NULL,
  sent_at         TEXT DEFAULT '',
  status          TEXT DEFAULT 'queued',  -- queued | sent | delivered | opened | clicked | replied | bounced | failed
  opens           INTEGER DEFAULT 0,
  clicks          INTEGER DEFAULT 0,
  replied         INTEGER DEFAULT 0,
  provider_id     TEXT DEFAULT '',        -- SendGrid message ID
  error_message   TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_outreach_email    ON outreach_log(lead_email);
CREATE INDEX IF NOT EXISTS idx_outreach_template ON outreach_log(template);
CREATE INDEX IF NOT EXISTS idx_outreach_status   ON outreach_log(status);
CREATE INDEX IF NOT EXISTS idx_outreach_sched    ON outreach_log(scheduled_at DESC);

-- ─── TRIALS ───────────────────────────────────────────────────────────────────
-- Active and past trials with conversion tracking
CREATE TABLE IF NOT EXISTS trials (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  name            TEXT DEFAULT '',
  company         TEXT DEFAULT '',
  api_key_suffix  TEXT DEFAULT '',  -- last 8 chars of API key for reference
  activated_at    TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  activated       INTEGER DEFAULT 1,
  converted       INTEGER DEFAULT 0,
  converted_at    TEXT DEFAULT '',
  nudge_sent_3d   INTEGER DEFAULT 0,
  nudge_sent_1d   INTEGER DEFAULT 0,
  nudge_sent_0d   INTEGER DEFAULT 0,
  usage_calls     INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_trials_expires ON trials(expires_at);
CREATE INDEX IF NOT EXISTS idx_trials_conv    ON trials(converted);

-- ─── SUBSCRIPTIONS ────────────────────────────────────────────────────────────
-- Active paying customers — synced from Stripe/Razorpay webhooks
CREATE TABLE IF NOT EXISTS subscriptions (
  id                  TEXT PRIMARY KEY,
  email               TEXT NOT NULL UNIQUE,
  company             TEXT DEFAULT '',
  plan                TEXT NOT NULL,       -- pro | enterprise
  status              TEXT DEFAULT 'active',  -- active | past_due | cancelled | paused
  billing_provider    TEXT DEFAULT 'razorpay', -- razorpay | stripe
  provider_sub_id     TEXT DEFAULT '',
  amount_inr          INTEGER DEFAULT 0,
  amount_usd          INTEGER DEFAULT 0,
  billing_cycle       TEXT DEFAULT 'monthly', -- monthly | annual
  current_period_start TEXT DEFAULT '',
  current_period_end   TEXT DEFAULT '',
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL,
  cancelled_at        TEXT DEFAULT '',
  cancel_reason       TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_subs_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_subs_plan   ON subscriptions(plan);
CREATE INDEX IF NOT EXISTS idx_subs_email  ON subscriptions(email);

-- ─── API USAGE ────────────────────────────────────────────────────────────────
-- Per-key daily API usage — joined with leads for upsell triggers
CREATE TABLE IF NOT EXISTS api_usage (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  key_id      TEXT NOT NULL,
  email       TEXT DEFAULT '',
  tier        TEXT DEFAULT 'free',
  date        TEXT NOT NULL,              -- YYYY-MM-DD
  calls       INTEGER DEFAULT 0,
  limit_hit   INTEGER DEFAULT 0,          -- 1 = hit daily cap
  endpoints   TEXT DEFAULT '{}',          -- JSON: {"feed":N,"ai":N,"stix":N}
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_usage_key_date ON api_usage(key_id, date);
CREATE INDEX IF NOT EXISTS idx_usage_email ON api_usage(email);
CREATE INDEX IF NOT EXISTS idx_usage_limit ON api_usage(limit_hit);

-- ─── REVENUE EVENTS ───────────────────────────────────────────────────────────
-- All monetization events — upgrade triggers, conversions, churn signals
CREATE TABLE IF NOT EXISTS events (
  id          TEXT PRIMARY KEY,
  event       TEXT NOT NULL,  -- lead_captured|trial_activated|upgrade_trigger|deal_closed|churned
  meta        TEXT DEFAULT '{}',
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event);
CREATE INDEX IF NOT EXISTS idx_events_date ON events(created_at DESC);

-- ─── REVENUE MRR SNAPSHOTS ────────────────────────────────────────────────────
-- Daily MRR snapshots for trend tracking
CREATE TABLE IF NOT EXISTS mrr_snapshots (
  date            TEXT PRIMARY KEY,  -- YYYY-MM-DD
  mrr_inr         INTEGER DEFAULT 0,
  mrr_usd         INTEGER DEFAULT 0,
  pro_count       INTEGER DEFAULT 0,
  enterprise_count INTEGER DEFAULT 0,
  trial_count     INTEGER DEFAULT 0,
  churned_inr     INTEGER DEFAULT 0,
  new_mrr_inr     INTEGER DEFAULT 0,
  target_inr      INTEGER DEFAULT 1000000
);

-- ─── DEMO REQUESTS ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS demos (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  name            TEXT DEFAULT '',
  company         TEXT NOT NULL,
  team_size       TEXT DEFAULT '',
  use_case        TEXT DEFAULT '',
  demo_link       TEXT DEFAULT '',
  status          TEXT DEFAULT 'pending',  -- pending | confirmed | completed | no_show
  requested_at    TEXT NOT NULL,
  confirmed_at    TEXT DEFAULT '',
  completed_at    TEXT DEFAULT '',
  deal_id         TEXT DEFAULT '',
  notes           TEXT DEFAULT ''
);

-- ─── VIEWS — Revenue dashboarding ─────────────────────────────────────────────

-- Active pipeline summary
CREATE VIEW IF NOT EXISTS pipeline_summary AS
SELECT
  stage,
  COUNT(*)                        AS deal_count,
  SUM(value_inr)                  AS total_value_inr,
  SUM(weighted_value_inr)         AS weighted_value_inr,
  AVG(close_probability)          AS avg_probability,
  MAX(updated_at)                 AS last_updated
FROM deals
WHERE stage NOT IN ('closed_lost')
GROUP BY stage
ORDER BY
  CASE stage
    WHEN 'new'             THEN 1
    WHEN 'contacted'       THEN 2
    WHEN 'demo_scheduled'  THEN 3
    WHEN 'demo_done'       THEN 4
    WHEN 'trial'           THEN 5
    WHEN 'negotiation'     THEN 6
    WHEN 'closed_won'      THEN 7
  END;

-- Monthly revenue by plan
CREATE VIEW IF NOT EXISTS mrr_by_plan AS
SELECT
  plan,
  COUNT(*)             AS subscriber_count,
  SUM(amount_inr)      AS total_mrr_inr,
  SUM(amount_usd)      AS total_mrr_usd,
  AVG(amount_inr)      AS avg_arpu_inr
FROM subscriptions
WHERE status = 'active'
GROUP BY plan;

-- Lead funnel conversion
CREATE VIEW IF NOT EXISTS lead_funnel AS
SELECT
  status,
  COUNT(*)             AS count,
  AVG(score)           AS avg_score,
  SUM(CASE WHEN converted=1 THEN 1 ELSE 0 END) AS converted_count
FROM leads
GROUP BY status
ORDER BY count DESC;

-- ─── SEED: Revenue targets ────────────────────────────────────────────────────
INSERT OR IGNORE INTO mrr_snapshots (date, mrr_inr, mrr_usd, target_inr)
VALUES (date('now'), 0, 0, 1000000);
