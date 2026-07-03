-- ASL V6 Schema Migration: Benchmark Runs + False Positive Overrides
-- Append to the end of infrastructure/supabase/schema.sql
-- Run in Supabase SQL Editor after the main schema

-- ============================================================
-- BENCHMARK RUNS
-- Tracks scan quality metrics per scan for ongoing FP rate monitoring
-- ============================================================
CREATE TABLE benchmark_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Raw pipeline output
    total_raw_findings INTEGER NOT NULL DEFAULT 0,
    after_stage1_reachability INTEGER NOT NULL DEFAULT 0,
    after_stage2_confidence INTEGER NOT NULL DEFAULT 0,
    after_stage3_corroboration INTEGER NOT NULL DEFAULT 0,
    after_stage4_dedup INTEGER NOT NULL DEFAULT 0,
    after_stage5_ai_review INTEGER NOT NULL DEFAULT 0,
    
    -- Computed metrics
    false_positive_rate_pct NUMERIC(5,2),
    noise_reduction_pct NUMERIC(5,2),
    
    -- AI frameworks detected
    frameworks_detected TEXT[] DEFAULT '{}',
    
    -- Layer timing (seconds)
    layer_timing JSONB DEFAULT '{}',
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_benchmark_runs_scan_id ON benchmark_runs(scan_id);
CREATE INDEX idx_benchmark_runs_org_id ON benchmark_runs(organization_id);
CREATE INDEX idx_benchmark_runs_created ON benchmark_runs(created_at DESC);

-- RLS
ALTER TABLE benchmark_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Org members can view benchmark runs" ON benchmark_runs
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = benchmark_runs.organization_id
            AND user_id = auth.uid()
        )
    );

-- ============================================================
-- FALSE POSITIVE OVERRIDES
-- Human-in-the-loop feedback: users can confirm TP/FP to improve future scans
-- ============================================================
CREATE TABLE false_positive_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Override verdict
    verdict TEXT NOT NULL CHECK (verdict IN ('confirmed_true_positive', 'confirmed_false_positive')),
    reasoning TEXT,
    
    -- The finding context at time of override (for ML training)
    vulnerability_class TEXT,
    code_snippet TEXT,
    ai_confidence_at_override NUMERIC(5,4),
    
    -- Feedback used to retrain confidence scorer
    feedback_applied BOOLEAN DEFAULT false,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_fp_overrides_finding ON false_positive_overrides(finding_id);
CREATE INDEX idx_fp_overrides_org ON false_positive_overrides(organization_id);
CREATE INDEX idx_fp_overrides_verdict ON false_positive_overrides(verdict);

-- RLS
ALTER TABLE false_positive_overrides ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can manage own FP overrides" ON false_positive_overrides
    FOR ALL USING (user_id = auth.uid());
CREATE POLICY "Org members can view FP overrides" ON false_positive_overrides
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = false_positive_overrides.organization_id
            AND user_id = auth.uid()
        )
    );

-- ============================================================
-- AGGREGATE VIEW: Organization FP Rate over last 30 days
-- ============================================================
CREATE OR REPLACE VIEW org_fp_metrics AS
SELECT
    br.organization_id,
    COUNT(*) AS scans_analyzed,
    AVG(br.false_positive_rate_pct) AS avg_fp_rate_pct,
    AVG(br.noise_reduction_pct) AS avg_noise_reduction_pct,
    SUM(br.total_raw_findings) AS total_raw,
    SUM(br.after_stage5_ai_review) AS total_verified,
    MAX(br.created_at) AS last_scan_at
FROM benchmark_runs br
WHERE br.created_at > NOW() - INTERVAL '30 days'
GROUP BY br.organization_id;
