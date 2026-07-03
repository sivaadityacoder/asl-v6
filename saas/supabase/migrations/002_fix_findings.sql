-- Fix findings table (reserved keyword 'references' renamed to 'reference_urls')
CREATE TABLE IF NOT EXISTS public.findings (
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

-- Add missing indexes for findings
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON public.findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON public.findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON public.findings(status);

-- Add trigger for findings
CREATE TRIGGER update_findings_updated_at 
  BEFORE UPDATE ON public.findings 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Enable RLS for findings
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

-- Grant permissions for findings
GRANT ALL ON public.findings TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.findings TO authenticated;
GRANT SELECT ON public.findings TO anon;
