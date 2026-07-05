'use client';

import { useState, useEffect } from 'react';
import { GitBranch, Loader2, CheckCircle2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchApi } from '@/lib/api';
import { useSession } from 'next-auth/react';
import Link from 'next/link';

export default function RepositoriesConnectPagePage() {
  const { data: session } = useSession();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    if (!session?.access_token) {
      setStatus('error');
      setMessage('You must be logged in');
      return;
    }

    setLoading(true);
    setStatus('idle');
    try {
      // 1. Get orgs
      const orgsRes = await fetchApi('/api/v1/organizations/', {}, session.access_token);
      let orgId = orgsRes.organizations?.[0]?.id;

      if (!orgId) {
        // Create org
        const newOrg = await fetchApi('/api/v1/organizations/', {
          method: 'POST',
          body: JSON.stringify({ name: 'Default Org', slug: 'default-org-' + Date.now() })
        }, session.access_token);
        orgId = newOrg.id;
      }

      // 2. Get projects
      const projRes = await fetchApi(`/api/v1/projects/?organization_id=${orgId}`, {}, session.access_token);
      let projId = projRes.projects?.[0]?.id;

      if (!projId) {
        // Create project
        const newProj = await fetchApi(`/api/v1/projects/?organization_id=${orgId}`, {
          method: 'POST',
          body: JSON.stringify({ name: 'Default Project', slug: 'default-proj-' + Date.now() })
        }, session.access_token);
        projId = newProj.id;
      }

      // Parse URL (e.g. https://github.com/expressjs/express)
      const parts = url.replace('https://github.com/', '').split('/');
      const owner = parts[0] || 'unknown';
      const name = parts[1]?.replace('.git', '') || 'repo';

      // 3. Connect Repo
      await fetchApi(`/api/v1/repositories/connect?project_id=${projId}`, {
        method: 'POST',
        body: JSON.stringify({
          github_repo_id: `manual-${Date.now()}`,
          owner,
          name,
          full_name: `${owner}/${name}`,
          url,
          clone_url: url + '.git',
          default_branch: 'main',
          is_private: false
        })
      }, session.access_token);

      setStatus('success');
      setMessage(`Successfully connected ${owner}/${name}!`);
    } catch (err: any) {
      console.error(err);
      setStatus('error');
      setMessage(err.message || 'Failed to connect repository');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Connect Repository</h1>
        <p className="text-muted-foreground mt-1">Connect a new GitHub repository for scanning</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GitBranch className="h-5 w-5 text-primary" />
            Repository Details
          </CardTitle>
          <CardDescription>
            Enter the public GitHub URL of the repository you want to scan.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {status === 'success' ? (
            <div className="text-center py-6 space-y-4">
              <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto" />
              <h3 className="text-xl font-medium">{message}</h3>
              <div className="pt-4 flex justify-center gap-4">
                <Button asChild variant="outline">
                  <Link href="/dashboard">Back to Dashboard</Link>
                </Button>
                <Button asChild>
                  <Link href="/dashboard/scans/new">Start a Scan</Link>
                </Button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleConnect} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url">GitHub Repository URL</Label>
                <Input 
                  id="url" 
                  placeholder="https://github.com/owner/repo" 
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  required
                />
              </div>
              
              {status === 'error' && (
                <div className="text-sm font-medium text-red-500 p-3 bg-red-500/10 rounded-md">
                  {message}
                </div>
              )}

              <Button type="submit" className="w-full" disabled={loading || !url}>
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Connecting...
                  </>
                ) : (
                  'Connect Repository'
                )}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
