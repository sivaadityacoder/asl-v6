-- ASL V6 SaaS - Supabase Storage Buckets and Policies
-- Run these in Supabase Dashboard > Storage > Policies

-- ============================================================
-- CREATE BUCKETS (Run in SQL Editor)
-- ============================================================
-- Note: Create buckets via Supabase Dashboard or use the Storage API
-- Bucket names: reports, uploads, logs, screenshots
-- All buckets should be PRIVATE (not public)

-- ============================================================
-- REPORTS BUCKET POLICIES
-- ============================================================
-- Org members can upload reports for their scans
CREATE POLICY "Org members can upload reports" ON storage.objects
    FOR INSERT WITH CHECK (
        bucket_id = 'reports' AND
        auth.role() = 'authenticated' AND
        EXISTS (
            SELECT 1 FROM reports r
            JOIN organization_members om ON om.organization_id = r.organization_id
            WHERE om.user_id = auth.uid()
            AND r.file_path = storage.objects.name
        )
    );

-- Org members can view their own reports
CREATE POLICY "Org members can view reports" ON storage.objects
    FOR SELECT USING (
        bucket_id = 'reports' AND
        EXISTS (
            SELECT 1 FROM reports r
            JOIN organization_members om ON om.organization_id = r.organization_id
            WHERE om.user_id = auth.uid()
            AND r.file_path = storage.objects.name
        )
    );

-- Org members can update their own reports
CREATE POLICY "Org members can update reports" ON storage.objects
    FOR UPDATE USING (
        bucket_id = 'reports' AND
        EXISTS (
            SELECT 1 FROM reports r
            JOIN organization_members om ON om.organization_id = r.organization_id
            WHERE om.user_id = auth.uid()
            AND r.file_path = storage.objects.name
        )
    );

-- Org admins can delete reports
CREATE POLICY "Org admins can delete reports" ON storage.objects
    FOR DELETE USING (
        bucket_id = 'reports' AND
        EXISTS (
            SELECT 1 FROM reports r
            JOIN organization_members om ON om.organization_id = r.organization_id
            WHERE om.user_id = auth.uid()
            AND om.role IN ('owner', 'admin')
            AND r.file_path = storage.objects.name
        )
    );

-- ============================================================
-- UPLOADS BUCKET POLICIES
-- ============================================================
-- Org members can upload files
CREATE POLICY "Org members can upload files" ON storage.objects
    FOR INSERT WITH CHECK (
        bucket_id = 'uploads' AND
        auth.role() = 'authenticated' AND
        (storage.foldername(name))[1] IN (
            SELECT organization_id::text FROM organization_members WHERE user_id = auth.uid()
        )
    );

-- Org members can view their uploads
CREATE POLICY "Org members can view uploads" ON storage.objects
    FOR SELECT USING (
        bucket_id = 'uploads' AND
        (storage.foldername(name))[1] IN (
            SELECT organization_id::text FROM organization_members WHERE user_id = auth.uid()
        )
    );

-- Org members can update their uploads
CREATE POLICY "Org members can update uploads" ON storage.objects
    FOR UPDATE USING (
        bucket_id = 'uploads' AND
        (storage.foldername(name))[1] IN (
            SELECT organization_id::text FROM organization_members WHERE user_id = auth.uid()
        )
    );

-- Org admins can delete uploads
CREATE POLICY "Org admins can delete uploads" ON storage.objects
    FOR DELETE USING (
        bucket_id = 'uploads' AND
        (storage.foldername(name))[1] IN (
            SELECT organization_id::text FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

-- ============================================================
-- LOGS BUCKET POLICIES
-- ============================================================
-- Service role (backend) can write logs
CREATE POLICY "Service role can write logs" ON storage.objects
    FOR INSERT WITH CHECK (
        bucket_id = 'logs' AND
        auth.role() = 'service_role'
    );

-- Org admins can view logs
CREATE POLICY "Org admins can view logs" ON storage.objects
    FOR SELECT USING (
        bucket_id = 'logs' AND
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
            AND organization_id::text = (storage.foldername(name))[1]
        )
    );

-- ============================================================
-- SCREENSHOTS BUCKET POLICIES
-- ============================================================
-- Service role (backend) can write screenshots
CREATE POLICY "Service role can write screenshots" ON storage.objects
    FOR INSERT WITH CHECK (
        bucket_id = 'screenshots' AND
        auth.role() = 'service_role'
    );

-- Org members can view screenshots for their scans
CREATE POLICY "Org members can view screenshots" ON storage.objects
    FOR SELECT USING (
        bucket_id = 'screenshots' AND
        EXISTS (
            SELECT 1 FROM scans s
            JOIN organization_members om ON om.organization_id = s.organization_id
            WHERE om.user_id = auth.uid()
            AND s.id::text = (storage.foldername(name))[1]
        )
    );