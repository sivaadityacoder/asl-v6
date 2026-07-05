'use client';

import { useState, useEffect } from 'react';
import { 
  FolderGit, 
  GitBranch, 
  PlayCircle, 
  Shield, 
  FileText, 
  Loader2
} from 'lucide-react';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useSession } from 'next-auth/react';
import { fetchApi } from '@/lib/api';

function Badge({ children, variant = 'default', className = '' }: { children: React.ReactNode; variant?: string; className?: string }) {
  const base = 'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold';
  const variants: Record<string, string> = {
    default: 'bg-primary text-primary-foreground',
    secondary: 'bg-secondary text-secondary-foreground',
    destructive: 'bg-destructive text-destructive-foreground',
    outline: 'border border-input text-foreground',
    success: 'bg-green-500/10 text-green-500',
    warning: 'bg-yellow-500/10 text-yellow-600',
    critical: 'bg-red-500/10 text-red-500',
  };
  return <span className={cn(base, variants[variant] || variants.default, className)}>{children}</span>;
}

const statusColors: Record<string, string> = {
  completed: 'bg-green-500/10 text-green-500 border-green-500/20',
  running: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  failed: 'bg-red-500/10 text-red-500 border-red-500/20',
  queued: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  pending: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
};

export default function DashboardPage() {
  const { data: session } = useSession();
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState<any[]>([]);
  const [reposCount, setReposCount] = useState(0);

  useEffect(() => {
    if (session?.access_token) {
      loadDashboardData();
    }
  }, [session]);

  const loadDashboardData = async () => {
    try {
      // 1. Get Org & Project
      const orgsRes = await fetchApi('/api/v1/organizations/', {}, session!.access_token!);
      const orgId = orgsRes.organizations?.[0]?.id;
      if (!orgId) return;
      
      const projRes = await fetchApi(`/api/v1/projects/?organization_id=${orgId}`, {}, session!.access_token!);
      const projId = projRes.projects?.[0]?.id;
      if (!projId) return;

      // 2. Get Repos count
      const repoRes = await fetchApi(`/api/v1/repositories/?project_id=${projId}`, {}, session!.access_token!);
      setReposCount(repoRes.total || 0);

      // 3. Get Recent Scans
      const scanRes = await fetchApi(`/api/v1/scans/?project_id=${projId}&page_size=5`, {}, session!.access_token!);
      setScans(scanRes.scans || []);

    } catch (err) {
      console.error("Dashboard fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  const stats = [
    { name: 'Projects', value: '1', icon: FolderGit, color: 'text-blue-500', bg: 'bg-blue-500/10', change: 'Active' },
    { name: 'Repositories', value: reposCount.toString(), icon: GitBranch, color: 'text-green-500', bg: 'bg-green-500/10', change: 'Connected' },
    { name: 'Total Scans', value: scans.length.toString(), icon: PlayCircle, color: 'text-purple-500', bg: 'bg-purple-500/10', change: 'Recent history' },
    { name: 'Live Monitoring', value: 'ON', icon: Shield, color: 'text-orange-500', bg: 'bg-orange-500/10', change: 'Engine active' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground mt-1">Overview of your AI security posture</p>
        </div>
        <Button asChild>
          <Link href="/dashboard/scans/new">
            <PlayCircle className="h-4 w-4 mr-2" />
            New Scan
          </Link>
        </Button>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.name}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">{stat.name}</CardTitle>
              <div className={cn('h-10 w-10 rounded-lg flex items-center justify-center', stat.bg)}>
                <stat.icon className={cn('h-5 w-5', stat.color)} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stat.value}</div>
              <p className="text-xs text-muted-foreground">{stat.change}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Main Content */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recent Scans */}
        <Card className="col-span-full lg:col-span-1">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Recent Scans</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="flex justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : scans.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground">
                <p className="mb-4">No scans found.</p>
                <Button asChild variant="outline" size="sm">
                  <Link href="/dashboard/scans/new">Start your first scan</Link>
                </Button>
              </div>
            ) : (
              <div className="divide-y divide-border">
                {scans.map((scan) => (
                  <Link key={scan.id} href={`/dashboard/scans/${scan.id}`} className="flex items-center justify-between p-4 hover:bg-accent/50 transition-colors">
                    <div className="flex items-center gap-4">
                      <div className="h-10 w-10 rounded-lg bg-muted flex items-center justify-center">
                        <GitBranch className="h-5 w-5 text-muted-foreground" />
                      </div>
                      <div>
                        <p className="font-medium truncate max-w-[200px]">Repository Scan</p>
                        <p className="text-sm text-muted-foreground">
                          {scan.branch} • {new Date(scan.created_at).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge variant="outline" className={cn(statusColors[scan.status] || statusColors.queued)}>
                        {scan.status}
                      </Badge>
                      <span className="text-sm font-medium">
                        <span className="text-red-500">{scan.findings_count || 0} found</span>
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card className="col-span-full lg:col-span-1">
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <Button variant="outline" asChild className="h-auto p-4 flex flex-col items-start gap-2">
              <Link href="/dashboard/repositories/connect">
                <GitBranch className="h-6 w-6" />
                <span className="font-medium">Connect Repository</span>
                <span className="text-sm text-muted-foreground">Add a new GitHub repo to scan</span>
              </Link>
            </Button>
            <Button variant="outline" asChild className="h-auto p-4 flex flex-col items-start gap-2">
              <Link href="/dashboard/scans/new">
                <PlayCircle className="h-6 w-6" />
                <span className="font-medium">Start New Scan</span>
                <span className="text-sm text-muted-foreground">Run security scan on existing repo</span>
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}