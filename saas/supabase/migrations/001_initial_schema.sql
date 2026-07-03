-- ============================================================
-- ASL V6 SaaS - Initial Database Schema
-- Migration: 001_initial_schema.sql
-- ============================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- ENUMS
-- ============================================================

CREATE TYPE user_role AS ENUM ('owner', 'admin', 'member', 'viewer');
CREATE TYPE plan_tier AS ENUM ('starter', 'pro', 'team', 'enterprise');
CREATE TYPE scan_status AS ENUM (
  'pending', 'queued', 'cloning', 'discovery', 'static_analysis',
  'secrets_scan', 'reachability', 'context_analysis', 'owasp_llm',
  'mitre_atlas', 'dynamic_validation', 'ai_review', 'evidence_collection',
  'report_generation', 'completed', 'failed', 'cancelled'
);
CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE finding_status AS ENUM ('open', 'in_progress', 'fixed', 'false_positive', 'wont_fix', 'accepted_risk');
CREATE TYPE repository_provider AS ENUM ('github', 'gitlab', 'bitbucket');
CREATE TYPE report_format AS ENUM ('markdown', 'pdf', 'html', 'json', 'sarif');

-- ============================================================
-- USERS TABLE
-- ============================================================

CREATE TABLE public.users (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email                  TEXT UNIQUE NOT NULL,
  full_name              TEXT,
  avatar_url             TEXT,
  github_username        TEXT,
  github_id              BIGINT,
  role                   user_role NOT NULL DEFAULT 'member',
  plan_tier              plan_tier NOT NULL DEFAULT 'starter',
  stripe_customer_id     TEXT,
  stripe_subscription_id TEXT,
  is_active              BOOLEAN NOT NULL DEFAULT TRUE,
  last_login             TIMESTAMPTZ,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- ORGANIZATIONS
-- ============================================================

CREATE TABLE public.organizations (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL,
  slug             TEXT UNIQUE NOT NULL,
  description      TEXT,
  logo_url         TEXT,
  owner_id         UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  plan_tier        plan_tier NOT NULL DEFAULT 'starter',
  stripe_customer_id TEXT,
  settings         JSONB NOT NULL DEFAULT '{}',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.organization_members (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  role            user_role NOT NULL DEFAULT 'member',
  invited_by      UUID REFERENCES public.users(id),
  invited_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  joined_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(organization_id, user_id)
);

-- ============================================================
-- PROJECTS & REPOSITORIES
-- ============================================================

CREATE TABLE public.projects (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  slug            TEXT NOT NULL,
  description     TEXT,
  avatar_url      TEXT,
  settings        JSONB NOT NULL DEFAULT '{}',
  is_active       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(organization_id, slug)
);

CREATE TABLE public.repositories (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id       UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  provider         repository_provider NOT NULL DEFAULT 'github',
  provider_repo_id TEXT NOT NULL,
  owner            TEXT NOT NULL,
  name             TEXT NOT NULL,
  full_name        TEXT NOT NULL,
  url              TEXT NOT NULL,
  clone_url        TEXT NOT NULL,
  default_branch   TEXT NOT NULL DEFAULT 'main',
  description      TEXT,
  language         TEXT,
  stars            INTEGER NOT NULL DEFAULT 0,
  forks            INTEGER NOT NULL DEFAULT 0,
  size_kb          INTEGER NOT NULL DEFAULT 0,
  is_private       BOOLEAN NOT NULL DEFAULT TRUE,
  is_archived      BOOLEAN NOT NULL DEFAULT FALSE,
  is_fork          BOOLEAN NOT NULL DEFAULT FALSE,
  webhook_id       BIGINT,
  last_synced_at   TIMESTAMPTZ,
  settings         JSONB NOT NULL DEFAULT '{}',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SCANS
-- ============================================================

CREATE TABLE public.scans (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id   UUID NOT NULL REFERENCES public.repositories(id) ON DELETE CASCADE,
  project_id      UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  initiated_by    UUID NOT NULL REFERENCES public.users(id),
  commit_sha      TEXT NOT NULL,
  branch          TEXT NOT NULL,
  status          scan_status NOT NULL DEFAULT 'pending',
  progress        INTEGER NOT NULL DEFAULT 0,
  current_layer   INTEGER NOT NULL DEFAULT 0,
  total_layers    INTEGER NOT NULL DEFAULT 10,
  layer_status    JSONB NOT NULL DEFAULT '{}',
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  duration_seconds INTEGER,
  error_message   TEXT,
  findings_count  INTEGER NOT NULL DEFAULT 0,
  critical_count  INTEGER NOT NULL DEFAULT 0,
  high_count      INTEGER NOT NULL DEFAULT 0,
  medium_count    INTEGER NOT NULL DEFAULT 0,
  low_count       INTEGER NOT NULL DEFAULT 0,
  info_count      INTEGER NOT NULL DEFAULT 0,
  scan_config     JSONB NOT NULL DEFAULT '{}',
  celery_task_id  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- FINDINGS
-- ============================================================

CREATE TABLE public.findings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id         UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  repository_id   UUID NOT NULL REFERENCES public.repositories(id) ON DELETE CASCADE,
  project_id      UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  layer           INTEGER NOT NULL,
  layer_name      TEXT NOT NULL,
  rule_id         TEXT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT NOT NULL,
  severity        finding_severity NOT NULL,
  status          finding_status NOT NULL DEFAULT 'open',
  cvss_score      DECIMAL(4,1),
  cvss_vector     TEXT,
  cwe_id          TEXT,
  owasp_llm_id    TEXT,
  mitre_atlas_id  TEXT,
  file_path       TEXT,
  line_start      INTEGER,
  line_end        INTEGER,
  code_snippet    TEXT,
  evidence        JSONB NOT NULL DEFAULT '{}',
  remediation     TEXT,
  reference_urls  TEXT[] NOT NULL DEFAULT '{}',
  tags            TEXT[] NOT NULL DEFAULT '{}',
  confidence      DECIMAL(5,4),
  assigned_to     UUID REFERENCES public.users(id),
  triaged_by      UUID REFERENCES public.users(id),
  triaged_at      TIMESTAMPTZ,
  fixed_at        TIMESTAMPTZ,
  is_suppressed   BOOLEAN NOT NULL DEFAULT FALSE,
  suppression_reason TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- REPORTS
-- ============================================================

CREATE TABLE public.reports (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id         UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  project_id      UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  format          report_format NOT NULL,
  status          TEXT NOT NULL DEFAULT 'generating',
  file_path       TEXT,
  file_size       BIGINT,
  download_url    TEXT,
  expires_at      TIMESTAMPTZ,
  generated_at    TIMESTAMPTZ,
  error           TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- RULES
-- ============================================================

CREATE TABLE public.rules (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id      TEXT UNIQUE NOT NULL,
  name         TEXT NOT NULL,
  description  TEXT NOT NULL,
  category     TEXT NOT NULL,
  severity     finding_severity NOT NULL,
  layer        INTEGER NOT NULL,
  language     TEXT,
  pattern      TEXT,
  ast_pattern  JSONB,
  is_active    BOOLEAN NOT NULL DEFAULT TRUE,
  is_custom    BOOLEAN NOT NULL DEFAULT FALSE,
  created_by   UUID REFERENCES public.users(id),
  metadata     JSONB NOT NULL DEFAULT '{}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- BILLING
-- ============================================================

CREATE TABLE public.subscriptions (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id        UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  stripe_subscription_id TEXT UNIQUE NOT NULL,
  stripe_customer_id     TEXT NOT NULL,
  plan_tier              plan_tier NOT NULL,
  status                 TEXT NOT NULL,
  current_period_start   TIMESTAMPTZ NOT NULL,
  current_period_end     TIMESTAMPTZ NOT NULL,
  cancel_at_period_end   BOOLEAN NOT NULL DEFAULT FALSE,
  canceled_at            TIMESTAMPTZ,
  trial_end              TIMESTAMPTZ,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.invoices (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  stripe_invoice_id TEXT UNIQUE NOT NULL,
  amount          INTEGER NOT NULL,
  currency        TEXT NOT NULL DEFAULT 'usd',
  status          TEXT NOT NULL,
  invoice_url     TEXT,
  invoice_pdf     TEXT,
  period_start    TIMESTAMPTZ NOT NULL,
  period_end      TIMESTAMPTZ NOT NULL,
  paid_at         TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- AUDIT LOGS
-- ============================================================

CREATE TABLE public.audit_logs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id         UUID REFERENCES public.users(id) ON DELETE SET NULL,
  action          TEXT NOT NULL,
  resource_type   TEXT NOT NULL,
  resource_id     UUID,
  details         JSONB NOT NULL DEFAULT '{}',
  ip_address      INET,
  user_agent      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- WEBHOOKS
-- ============================================================

CREATE TABLE public.webhook_deliveries (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id      UUID NOT NULL,
  event_type      TEXT NOT NULL,
  payload         JSONB NOT NULL DEFAULT '{}',
  response_status INTEGER,
  response_body   TEXT,
  attempt         INTEGER NOT NULL DEFAULT 1,
  max_attempts    INTEGER NOT NULL DEFAULT 5,
  next_retry_at   TIMESTAMPTZ,
  succeeded_at    TIMESTAMPTZ,
  error           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX idx_users_email ON public.users(email);
CREATE INDEX idx_users_github_username ON public.users(github_username);
CREATE INDEX idx_organizations_slug ON public.organizations(slug);
CREATE INDEX idx_organizations_owner_id ON public.organizations(owner_id);
CREATE INDEX idx_org_members_org_id ON public.organization_members(organization_id);
CREATE INDEX idx_org_members_user_id ON public.organization_members(user_id);
CREATE INDEX idx_projects_org_id ON public.projects(organization_id);
CREATE INDEX idx_repositories_project_id ON public.repositories(project_id);
CREATE INDEX idx_scans_repository_id ON public.scans(repository_id);
CREATE INDEX idx_scans_project_id ON public.scans(project_id);
CREATE INDEX idx_scans_status ON public.scans(status);
CREATE INDEX idx_findings_scan_id ON public.findings(scan_id);
CREATE INDEX idx_findings_severity ON public.findings(severity);
CREATE INDEX idx_findings_status ON public.findings(status);
CREATE INDEX idx_reports_scan_id ON public.reports(scan_id);
CREATE INDEX idx_audit_logs_org_id ON public.audit_logs(organization_id);
CREATE INDEX idx_audit_logs_user_id ON public.audit_logs(user_id);

-- ============================================================
-- UPDATED_AT TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON public.organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_org_members_updated_at BEFORE UPDATE ON public.organization_members FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON public.projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_repositories_updated_at BEFORE UPDATE ON public.repositories FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON public.scans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON public.findings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_reports_updated_at BEFORE UPDATE ON public.reports FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_rules_updated_at BEFORE UPDATE ON public.rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON public.subscriptions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS (for backend)
-- Users can read/update their own profile
CREATE POLICY "Users can read own profile"
  ON public.users FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON public.users FOR UPDATE
  USING (auth.uid() = id);

-- Service role can do everything on users (backend)
CREATE POLICY "Service role full access to users"
  ON public.users
  USING (auth.jwt() ->> 'role' = 'service_role');

-- Organizations - members can read, owners can update
CREATE POLICY "Org members can read"
  ON public.organizations FOR SELECT
  USING (
    id IN (
      SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ) OR owner_id = auth.uid()
  );

-- Projects - org members can read
CREATE POLICY "Org members can read projects"
  ON public.projects FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    )
  );

-- ============================================================
-- GRANT PERMISSIONS
-- ============================================================

-- Grant to anon and authenticated roles
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO authenticated;
