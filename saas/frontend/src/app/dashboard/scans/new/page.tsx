'use client';

import { useState, useEffect } from 'react';
import { PlayCircle, Loader2, GitBranch, CheckCircle2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { fetchApi } from '@/lib/api';
import { useSession } from 'next-auth/react';
import Link from 'next/link';

export default function ScansNewPagePage() {
  const { data: session } = useSession();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [repos, setRepos] = useState<any[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<string>('');
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const [scanId, setScanId] = useState('');

  useEffect(() => {
    if (session?.access_token) {
      loadRepos();
    }
  }, [session]);

  const loadRepos = async () => {
    try {
      // 1. Get Org
      const orgsRes = await fetchApi('/api/v1/organizations/', {}, session!.access_token!);
      const orgId = orgsRes.organizations?.[0]?.id;
      if (!orgId) {
        setLoading(false);
        return;
      }
      
      // 2. Get Project
      const projRes = await fetchApi(`/api/v1/projects/?organization_id=${orgId}`, {}, session!.access_token!);
      const projId = projRes.projects?.[0]?.id;
      if (!projId) {
        setLoading(false);
        return;
      }

      // 3. Get Repos
      const repoRes = await fetchApi(`/api/v1/repositories/?project_id=${projId}`, {}, session!.access_token!);
      setRepos(repoRes.repositories || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRepo) return;
    
    setSubmitting(true);
    setStatus('idle');
    try {
      const res = await fetchApi(`/api/v1/scans/`, {
        method: 'POST',
        body: JSON.stringify({
          repository_id: selectedRepo,
          branch: 'main',
          scan_config: {
            ruleset: 'default',
            depth: 'full'
          }
        })
      }, session?.access_token!);
      
      setScanId(res.id);
      setStatus('success');
      setMessage('Scan started successfully!');
    } catch (err: any) {
      setStatus('error');
      setMessage(err.message || 'Failed to start scan');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">New Scan</h1>
        <p className="text-muted-foreground mt-1">Start a new security scan on one of your repositories</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <PlayCircle className="h-5 w-5 text-primary" />
            Configure Scan
          </CardTitle>
          <CardDescription>
            Select a connected repository to scan.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : status === 'success' ? (
            <div className="text-center py-6 space-y-4">
              <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto" />
              <h3 className="text-xl font-medium">{message}</h3>
              <p className="text-muted-foreground">The ASL V6 Engine is now analyzing your code.</p>
              <div className="pt-4 flex justify-center gap-4">
                <Button asChild variant="outline">
                  <Link href="/dashboard">Back to Dashboard</Link>
                </Button>
                <Button asChild>
                  <Link href={`/dashboard/scans/${scanId}`}>View Live Progress</Link>
                </Button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleStartScan} className="space-y-6">
              <div className="space-y-3">
                <Label>Repository</Label>
                {repos.length > 0 ? (
                  <select 
                    value={selectedRepo} 
                    onChange={(e) => setSelectedRepo(e.target.value)}
                    className="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <option value="" disabled>Select a repository</option>
                    {repos.map(repo => (
                      <option key={repo.id} value={repo.id}>
                        {repo.full_name}
                      </option>
                    ))}
                  </select>
                ) : (
                  <div className="p-4 border rounded-md bg-muted/30 text-center space-y-3">
                    <p className="text-sm text-muted-foreground">No repositories found in your project.</p>
                    <Button asChild variant="outline" size="sm">
                      <Link href="/dashboard/repositories/connect">Connect a Repository</Link>
                    </Button>
                  </div>
                )}
              </div>
              
              {status === 'error' && (
                <div className="text-sm font-medium text-red-500 p-3 bg-red-500/10 rounded-md">
                  {message}
                </div>
              )}

              <Button type="submit" className="w-full" disabled={submitting || !selectedRepo}>
                {submitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Starting ASL V6 Engine...
                  </>
                ) : (
                  'Start Scan'
                )}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
