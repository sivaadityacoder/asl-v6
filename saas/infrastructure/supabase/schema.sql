-- ASL V6 SaaS - Supabase Database Schema
-- Run this in Supabase SQL Editor

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

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
-- USERS & ORGANIZATIONS
-- ============================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    avatar_url TEXT,
    github_username TEXT,
    github_id BIGINT UNIQUE,
    role user_role DEFAULT 'member',
    plan_tier plan_tier DEFAULT 'starter',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    description TEXT,
    logo_url TEXT,
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    plan_tier plan_tier DEFAULT 'starter',
    stripe_customer_id TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE organization_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role user_role DEFAULT 'member',
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    invited_at TIMESTAMPTZ DEFAULT NOW(),
    joined_at TIMESTAMPTZ,
    UNIQUE(organization_id, user_id)
);

-- ============================================================
-- PROJECTS & REPOSITORIES
-- ============================================================
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    description TEXT,
    avatar_url TEXT,
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, slug)
);

CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    provider repository_provider DEFAULT 'github',
    provider_repo_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    full_name TEXT NOT NULL,
    url TEXT NOT NULL,
    clone_url TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    description TEXT,
    language TEXT,
    stars INT DEFAULT 0,
    forks INT DEFAULT 0,
    size_kb INT DEFAULT 0,
    is_private BOOLEAN DEFAULT true,
    is_archived BOOLEAN DEFAULT false,
    is_fork BOOLEAN DEFAULT false,
    webhook_id BIGINT,
    last_synced_at TIMESTAMPTZ,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(project_id, provider, provider_repo_id)
);

-- ============================================================
-- SCANS
-- ============================================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    initiated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    commit_sha TEXT NOT NULL,
    branch TEXT NOT NULL,
    status scan_status DEFAULT 'pending',
    progress INT DEFAULT 0,
    current_layer INT DEFAULT 0,
    total_layers INT DEFAULT 10,
    layer_status JSONB DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INT,
    error_message TEXT,
    findings_count INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    info_count INT DEFAULT 0,
    scan_config JSONB DEFAULT '{}',
    celery_task_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE scan_layers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    layer_number INT NOT NULL,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INT,
    findings_count INT DEFAULT 0,
    error TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(scan_id, layer_number)
);

-- ============================================================
-- FINDINGS
-- ============================================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    layer INT NOT NULL,
    layer_name TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity finding_severity NOT NULL,
    status finding_status DEFAULT 'open',
    cvss_score NUMERIC(3,1),
    cvss_vector TEXT,
    cwe_id TEXT,
    owasp_llm_id TEXT,
    mitre_atlas_id TEXT,
    file_path TEXT,
    line_start INT,
    line_end INT,
    code_snippet TEXT,
    evidence JSONB DEFAULT '{}',
    remediation TEXT,
    references TEXT[],
    tags TEXT[],
    confidence NUMERIC(3,2),
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    triaged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    triaged_at TIMESTAMPTZ,
    fixed_at TIMESTAMPTZ,
    is_suppressed BOOLEAN DEFAULT false,
    suppression_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- REPORTS
-- ============================================================
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    format report_format NOT NULL,
    status TEXT DEFAULT 'generating',
    file_path TEXT,
    file_size BIGINT,
    download_url TEXT,
    expires_at TIMESTAMPTZ,
    generated_at TIMESTAMPTZ,
    error TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- RULES
-- ============================================================
CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    severity finding_severity NOT NULL,
    layer INT NOT NULL,
    language TEXT,
    pattern TEXT,
    ast_pattern JSONB,
    is_active BOOLEAN DEFAULT true,
    is_custom BOOLEAN DEFAULT false,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- BILLING
-- ============================================================
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_subscription_id TEXT UNIQUE NOT NULL,
    stripe_customer_id TEXT NOT NULL,
    plan_tier plan_tier NOT NULL,
    status TEXT NOT NULL,
    current_period_start TIMESTAMPTZ NOT NULL,
    current_period_end TIMESTAMPTZ NOT NULL,
    cancel_at_period_end BOOLEAN DEFAULT false,
    canceled_at TIMESTAMPTZ,
    trial_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_invoice_id TEXT UNIQUE NOT NULL,
    amount INT NOT NULL,
    currency TEXT DEFAULT 'usd',
    status TEXT NOT NULL,
    invoice_url TEXT,
    invoice_pdf TEXT,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    paid_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- AUDIT LOG
-- ============================================================
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- WEBHOOKS
-- ============================================================
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT[] NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_triggered_at TIMESTAMPTZ,
    failure_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    response_status INT,
    response_body TEXT,
    attempt INT DEFAULT 1,
    max_attempts INT DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    succeeded_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- ============================================================
-- Users
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_github_id ON users(github_id);
CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id);

-- Organizations
CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_owner ON organizations(owner_id);

-- Organization Members
CREATE INDEX idx_org_members_org ON organization_members(organization_id);
CREATE INDEX idx_org_members_user ON organization_members(user_id);

-- Projects
CREATE INDEX idx_projects_org ON projects(organization_id);
CREATE INDEX idx_projects_slug ON projects(organization_id, slug);

-- Repositories
CREATE INDEX idx_repositories_project ON repositories(project_id);
CREATE INDEX idx_repositories_provider ON repositories(provider, provider_repo_id);

-- Scans
CREATE INDEX idx_scans_repository ON scans(repository_id);
CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_scans_org ON scans(organization_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- Scan Layers
CREATE INDEX idx_scan_layers_scan ON scan_layers(scan_id);

-- Findings
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_repository ON findings(repository_id);
CREATE INDEX idx_findings_org ON findings(organization_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_rule ON findings(rule_id);
CREATE INDEX idx_findings_layer ON findings(layer);
CREATE INDEX idx_findings_created ON findings(created_at DESC);

-- Reports
CREATE INDEX idx_reports_scan ON reports(scan_id);
CREATE INDEX idx_reports_org ON reports(organization_id);

-- Rules
CREATE INDEX idx_rules_category ON rules(category);
CREATE INDEX idx_rules_layer ON rules(layer);
CREATE INDEX idx_rules_active ON rules(is_active);

-- Subscriptions
CREATE INDEX idx_subscriptions_org ON subscriptions(organization_id);
CREATE INDEX idx_subscriptions_stripe ON subscriptions(stripe_subscription_id);

-- Audit Logs
CREATE INDEX idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);

-- Webhooks
CREATE INDEX idx_webhooks_org ON webhooks(organization_id);
CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(succeeded_at);

-- ============================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_layers ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;

-- Helper function to check if user is member of organization
CREATE OR REPLACE FUNCTION is_org_member(org_id UUID, user_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM organization_members
        WHERE organization_id = org_id AND user_id = user_id
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Users can see their own profile
CREATE POLICY "Users can view own profile" ON users
    FOR SELECT USING (auth.uid() = id);

-- Users can update own profile
CREATE POLICY "Users can update own profile" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Organization members can view organization
CREATE POLICY "Org members can view org" ON organizations
    FOR SELECT USING (is_org_member(id, auth.uid()));

-- Organization owners/admins can update organization
CREATE POLICY "Org admins can update org" ON organizations
    FOR UPDATE USING (
        is_org_member(id, auth.uid()) AND 
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Organization members can view members
CREATE POLICY "Org members can view members" ON organization_members
    FOR SELECT USING (is_org_member(organization_id, auth.uid()));

-- Org admins can manage members
CREATE POLICY "Org admins can manage members" ON organization_members
    FOR ALL USING (
        is_org_member(organization_id, auth.uid()) AND 
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organization_id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Project policies
CREATE POLICY "Org members can view projects" ON projects
    FOR SELECT USING (is_org_member(organization_id, auth.uid()));

CREATE POLICY "Org admins can manage projects" ON projects
    FOR ALL USING (
        is_org_member(organization_id, auth.uid()) AND 
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organization_id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Repository policies
CREATE POLICY "Org members can view repositories" ON repositories
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM projects
            WHERE projects.id = repositories.project_id
            AND is_org_member(projects.organization_id, auth.uid())
        )
    );

CREATE POLICY "Org admins can manage repositories" ON repositories
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM projects
            WHERE projects.id = repositories.project_id
            AND is_org_member(projects.organization_id, auth.uid())
            AND EXISTS (
                SELECT 1 FROM organization_members
                WHERE organization_id = projects.organization_id AND user_id = auth.uid()
                AND role IN ('owner', 'admin')
            )
        )
    );

-- Scan policies
CREATE POLICY "Org members can view scans" ON scans
    FOR SELECT USING (is_org_member(organization_id, auth.uid()));

CREATE POLICY "Org members can create scans" ON scans
    FOR INSERT WITH CHECK (is_org_member(organization_id, auth.uid()));

CREATE POLICY "Org admins can update scans" ON scans
    FOR UPDATE USING (
        is_org_member(organization_id, auth.uid()) AND 
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organization_id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Scan layers
CREATE POLICY "Org members can view scan layers" ON scan_layers
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = scan_layers.scan_id
            AND is_org_member(scans.organization_id, auth.uid())
        )
    );

-- Findings policies
CREATE POLICY "Org members can view findings" ON findings
    FOR SELECT USING (is_org_member(organization_id, auth.uid()));

CREATE POLICY "Org members can update findings status" ON findings
    FOR UPDATE USING (is_org_member(organization_id, auth.uid()));

-- Reports policies
CREATE POLICY "Org members can view reports" ON reports
    FOR SELECT USING (is_org_member(organization_id, auth.uid()));

CREATE POLICY "Org members can create reports" ON reports
    FOR INSERT WITH CHECK (is_org_member(organization_id, auth.uid()));

-- Rules (public read for active rules, org admins manage custom rules)
CREATE POLICY "Anyone can view active rules" ON rules
    FOR SELECT USING (is_active = true);

CREATE POLICY "Org admins can manage custom rules" ON rules
    FOR ALL USING (
        is_custom = true AND
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id IN (
                SELECT organization_id FROM projects WHERE id = created_by
            ) AND user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

-- Subscriptions
CREATE POLICY "Org admins can view subscriptions" ON subscriptions
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = subscriptions.organization_id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Invoices
CREATE POLICY "Org admins can view invoices" ON invoices
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = invoices.organization_id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Audit logs
CREATE POLICY "Org admins can view audit logs" ON audit_logs
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = audit_logs.organization_id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Webhooks
CREATE POLICY "Org admins can manage webhooks" ON webhooks
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = webhooks.organization_id AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Webhook deliveries
CREATE POLICY "Org admins can view webhook deliveries" ON webhook_deliveries
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM webhooks
            JOIN organization_members ON organization_members.organization_id = webhooks.organization_id
            WHERE webhooks.id = webhook_deliveries.webhook_id
            AND organization_members.user_id = auth.uid()
            AND organization_members.role IN ('owner', 'admin')
        )
    );

-- ============================================================
-- TRIGGERS
-- ============================================================
-- Updated at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organization_members_updated_at BEFORE UPDATE ON organization_members FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_repositories_updated_at BEFORE UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_reports_updated_at BEFORE UPDATE ON reports FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_rules_updated_at BEFORE UPDATE ON rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_webhooks_updated_at BEFORE UPDATE ON webhooks FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- STORAGE BUCKETS (Run in Supabase Storage UI or via API)
-- ============================================================
-- Buckets to create:
-- 1. reports (private) - for generated reports
-- 2. uploads (private) - for user uploads
-- 3. logs (private) - for scan logs
-- 4. screenshots (private) - for dynamic validation screenshots

-- Example RLS policies for storage (run after creating buckets):
-- CREATE POLICY "Org members can view own reports" ON storage.objects
--     FOR SELECT USING (
--         bucket_id = 'reports' AND
--         EXISTS (
--             SELECT 1 FROM reports
--             WHERE reports.file_path = storage.objects.name
--             AND EXISTS (
--                 SELECT 1 FROM organization_members
--                 WHERE organization_id = reports.organization_id
--                 AND user_id = auth.uid()
--             )
--         )
--     );