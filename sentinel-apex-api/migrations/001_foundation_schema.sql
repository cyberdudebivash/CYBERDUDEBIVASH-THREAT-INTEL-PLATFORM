-- ============================================================================
-- SENTINEL APEX FOUNDATION SCHEMA v1.0
-- CYBERDUDEBIVASH PVT LTD — Production Migration
-- Execute in Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

CREATE TYPE subscription_tier AS ENUM ('free', 'pro', 'enterprise', 'mssp');
CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');
CREATE TYPE api_key_status AS ENUM ('active', 'revoked', 'expired');
CREATE TYPE advisory_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- ============================================================================
-- ORGANIZATIONS (Multi-tenant foundation)
-- ============================================================================

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    tier subscription_tier NOT NULL DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    max_users INTEGER NOT NULL DEFAULT 1,
    max_api_calls_daily INTEGER NOT NULL DEFAULT 10,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_org_slug ON organizations(slug);
CREATE INDEX idx_org_stripe ON organizations(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;

-- ============================================================================
-- USER PROFILES (extends Supabase auth.users)
-- ============================================================================

CREATE TABLE user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    full_name TEXT,
    role user_role NOT NULL DEFAULT 'viewer',
    is_org_owner BOOLEAN NOT NULL DEFAULT FALSE,
    avatar_url TEXT,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_profile_org ON user_profiles(org_id);
CREATE INDEX idx_profile_email ON user_profiles(email);

-- ============================================================================
-- API KEYS
-- ============================================================================

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT 'Default',
    status api_key_status NOT NULL DEFAULT 'active',
    tier subscription_tier NOT NULL DEFAULT 'free',
    rate_limit_daily INTEGER NOT NULL DEFAULT 10,
    scopes TEXT[] DEFAULT ARRAY['feed:read'],
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_apikey_hash ON api_keys(key_hash) WHERE status = 'active';
CREATE INDEX idx_apikey_org ON api_keys(org_id);

-- ============================================================================
-- ADVISORIES (Core intelligence data)
-- ============================================================================

CREATE TABLE advisories (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    summary_ai TEXT,
    risk_score NUMERIC(5,2),
    confidence NUMERIC(5,4),
    severity advisory_severity,
    cvss NUMERIC(4,2),
    epss NUMERIC(6,5),
    kev BOOLEAN DEFAULT FALSE,
    cve_id TEXT,
    mitre_techniques JSONB DEFAULT '[]',
    iocs JSONB DEFAULT '[]',
    stix_bundle_url TEXT,
    defense_kit JSONB DEFAULT '{}',
    source TEXT,
    source_url TEXT,
    tags TEXT[] DEFAULT '{}',
    published_at TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    search_vector TSVECTOR
);

CREATE INDEX idx_advisory_severity ON advisories(severity);
CREATE INDEX idx_advisory_risk ON advisories(risk_score DESC);
CREATE INDEX idx_advisory_published ON advisories(published_at DESC);
CREATE INDEX idx_advisory_cve ON advisories(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_advisory_kev ON advisories(kev) WHERE kev = TRUE;
CREATE INDEX idx_advisory_source ON advisories(source);
CREATE INDEX idx_advisory_ingested ON advisories(ingested_at DESC);
CREATE INDEX idx_advisory_search ON advisories USING GIN(search_vector);
CREATE INDEX idx_advisory_tags ON advisories USING GIN(tags);
CREATE INDEX idx_advisory_mitre ON advisories USING GIN(mitre_techniques);

CREATE OR REPLACE FUNCTION advisories_search_vector_update() RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        COALESCE(NEW.title, '') || ' ' ||
        COALESCE(NEW.description, '') || ' ' ||
        COALESCE(NEW.cve_id, '') || ' ' ||
        COALESCE(NEW.source, '') || ' ' ||
        COALESCE(array_to_string(NEW.tags, ' '), '')
    );
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_advisories_search
    BEFORE INSERT OR UPDATE ON advisories
    FOR EACH ROW EXECUTE FUNCTION advisories_search_vector_update();

-- ============================================================================
-- API USAGE TRACKING
-- ============================================================================

CREATE TABLE api_usage (
    id BIGSERIAL PRIMARY KEY,
    api_key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    status_code INTEGER,
    response_time_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_usage_key_date ON api_usage(api_key_id, created_at DESC);
CREATE INDEX idx_usage_org_date ON api_usage(org_id, created_at DESC);

-- ============================================================================
-- AUDIT LOG
-- ============================================================================

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES user_profiles(id),
    org_id UUID REFERENCES organizations(id),
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details JSONB DEFAULT '{}',
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_log(org_id, created_at DESC);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users read own org" ON organizations
    FOR SELECT USING (id IN (SELECT org_id FROM user_profiles WHERE id = auth.uid()));

CREATE POLICY "Org owners update org" ON organizations
    FOR UPDATE USING (id IN (SELECT org_id FROM user_profiles WHERE id = auth.uid() AND is_org_owner = TRUE));

CREATE POLICY "Users read org profiles" ON user_profiles
    FOR SELECT USING (org_id IN (SELECT org_id FROM user_profiles WHERE id = auth.uid()));

CREATE POLICY "Users update own profile" ON user_profiles
    FOR UPDATE USING (id = auth.uid());

CREATE POLICY "Org members read keys" ON api_keys
    FOR SELECT USING (org_id IN (SELECT org_id FROM user_profiles WHERE id = auth.uid()));

CREATE POLICY "Admins manage keys" ON api_keys
    FOR ALL USING (org_id IN (
        SELECT org_id FROM user_profiles WHERE id = auth.uid() AND (role = 'admin' OR is_org_owner = TRUE)
    ));

CREATE POLICY "Org members read usage" ON api_usage
    FOR SELECT USING (org_id IN (SELECT org_id FROM user_profiles WHERE id = auth.uid()));

CREATE POLICY "Org members read audit" ON audit_log
    FOR SELECT USING (org_id IN (SELECT org_id FROM user_profiles WHERE id = auth.uid()));

-- ============================================================================
-- AUTO-CREATE ORG + PROFILE ON SIGNUP
-- ============================================================================

CREATE OR REPLACE FUNCTION handle_new_user() RETURNS TRIGGER AS $$
DECLARE
    v_org_id UUID;
    v_name TEXT;
BEGIN
    v_name := COALESCE(
        NEW.raw_user_meta_data->>'full_name',
        NEW.raw_user_meta_data->>'name',
        split_part(NEW.email, '@', 1)
    );
    INSERT INTO organizations (name, slug, tier)
    VALUES (v_name || '''s Workspace', 'org-' || substr(NEW.id::text, 1, 8), 'free')
    RETURNING id INTO v_org_id;

    INSERT INTO user_profiles (id, org_id, email, full_name, role, is_org_owner)
    VALUES (NEW.id, v_org_id, NEW.email, v_name, 'admin', TRUE);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- ============================================================================
-- TIER CONFIGURATION REFERENCE
-- ============================================================================

CREATE TABLE tier_config (
    tier subscription_tier PRIMARY KEY,
    max_users INTEGER NOT NULL,
    max_api_calls_daily INTEGER NOT NULL,
    max_feed_results INTEGER NOT NULL,
    stix_downloads_daily INTEGER NOT NULL,
    ai_summaries_daily INTEGER NOT NULL,
    search_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    webhooks_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    custom_alerts_max INTEGER NOT NULL DEFAULT 0,
    price_monthly_cents INTEGER NOT NULL DEFAULT 0,
    stripe_price_id TEXT
);

INSERT INTO tier_config VALUES
    ('free',       1,  10,   10,  0,  3,  FALSE, FALSE, 0,  0,      NULL),
    ('pro',        5,  1000, 100, 50, -1, TRUE,  FALSE, 5,  4900,   NULL),
    ('enterprise', 25, -1,   -1,  -1, -1, TRUE,  TRUE,  -1, 49900,  NULL),
    ('mssp',       -1, -1,   -1,  -1, -1, TRUE,  TRUE,  -1, 199900, NULL);

-- ============================================================================
-- DAILY USAGE COUNT FUNCTION (for rate limiting)
-- ============================================================================

CREATE OR REPLACE FUNCTION get_daily_usage(p_api_key_id UUID, p_endpoint TEXT DEFAULT NULL)
RETURNS INTEGER AS $$
DECLARE v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count FROM api_usage
    WHERE api_key_id = p_api_key_id
      AND created_at >= DATE_TRUNC('day', NOW())
      AND (p_endpoint IS NULL OR endpoint = p_endpoint);
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;
