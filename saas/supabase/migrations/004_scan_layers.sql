CREATE TABLE public.scan_layers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    layer_number INTEGER NOT NULL,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'pending' NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    findings_count INTEGER DEFAULT 0 NOT NULL,
    error TEXT,
    metadata JSONB DEFAULT '{}'::jsonb NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

ALTER TABLE public.scan_layers ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their organization's scan layers"
    ON public.scan_layers FOR SELECT
    USING (
        scan_id IN (
            SELECT id FROM public.scans 
            WHERE organization_id IN (
                SELECT organization_id FROM public.organization_members 
                WHERE user_id = auth.uid()
            )
        )
    );

GRANT ALL ON public.scan_layers TO authenticated;
GRANT ALL ON public.scan_layers TO service_role;
