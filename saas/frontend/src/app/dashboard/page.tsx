'use client';

import { 
  FolderGit, 
  GitBranch, 
  PlayCircle, 
  Shield, 
  FileText, 
  TrendingUp,
  Clock,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';

// Inline Badge since @radix-ui/react-badge is not a real package (shadcn uses its own)
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

const stats = [
  { name: 'Projects', value: '12', icon: FolderGit, color: 'text-blue-500', bg: 'bg-blue-500/10', change: '+2 this month' },
  { name: 'Repositories', value: '47', icon: GitBranch, color: 'text-green-500', bg: 'bg-green-500/10', change: '+5 this month' },
  { name: 'Scans (30d)', value: '234', icon: PlayCircle, color: 'text-purple-500', bg: 'bg-purple-500/10', change: '+12% vs last month' },
  { name: 'Open Findings', value: '89', icon: Shield, color: 'text-orange-500', bg: 'bg-orange-500/10', change: '12 critical, 23 high' },
];

const recentScans = [
  { id: 'scan-1', repo: 'asl-security/llm-gateway', branch: 'main', commit: 'a1b2c3d', status: 'completed', findings: { critical: 2, high: 5, medium: 12, low: 8 }, started: '2 hours ago', duration: '4m 32s' },
  { id: 'scan-2', repo: 'company/rag-service', branch: 'feature/auth', commit: 'e4f5g6h', status: 'running', findings: { critical: 0, high: 2, medium: 5, low: 3 }, started: '5 min ago', duration: '—' },
  { id: 'scan-3', repo: 'team/agent-orchestrator', branch: 'main', commit: 'i7j8k9l', status: 'failed', findings: { critical: 0, high: 0, medium: 0, low: 0 }, started: '1 day ago', duration: '—' },
  { id: 'scan-4', repo: 'org/mcp-server', branch: 'develop', commit: 'm0n1o2p', status: 'completed', findings: { critical: 1, high: 3, medium: 7, low: 4 }, started: '3 days ago', duration: '6m 15s' },
];

const topFindings = [
  { id: 'f-1', title: 'Prompt Injection in User Input', severity: 'critical', repo: 'asl-security/llm-gateway', layer: 'OWASP LLM Top 10', rule: 'LLM01-001' },
  { id: 'f-2', title: 'Missing Namespace Isolation in Vector DB', severity: 'high', repo: 'company/rag-service', layer: 'Context Analysis', rule: 'RAG-003' },
  { id: 'f-3', title: 'Unsafe Tool Execution via MCP', severity: 'high', repo: 'team/agent-orchestrator', layer: 'Static Analysis', rule: 'MCP-007' },
  { id: 'f-4', title: 'Hardcoded API Key in Config', severity: 'medium', repo: 'org/mcp-server', layer: 'Secrets Scanning', rule: 'SEC-012' },
  { id: 'f-5', title: 'Agent Goal Hijacking Possible', severity: 'medium', repo: 'asl-security/llm-gateway', layer: 'Context Analysis', rule: 'AGN-002' },
];

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  low: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
};

const statusColors: Record<string, string> = {
  completed: 'bg-green-500/10 text-green-500 border-green-500/20',
  running: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  failed: 'bg-red-500/10 text-red-500 border-red-500/20',
  queued: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
};

export default function DashboardPage() {
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
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Recent Scans</CardTitle>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/dashboard/scans">View all</Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              {recentScans.map((scan) => (
                <Link key={scan.id} href={`/dashboard/scans/${scan.id}`} className="flex items-center justify-between p-4 hover:bg-accent/50 transition-colors">
                  <div className="flex items-center gap-4">
                    <div className="h-10 w-10 rounded-lg bg-muted flex items-center justify-center">
                      <GitBranch className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div>
                      <p className="font-medium truncate max-w-[200px]">{scan.repo}</p>
                      <p className="text-sm text-muted-foreground">
                        {scan.branch} • {scan.commit} • {scan.started}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className={cn(statusColors[scan.status])}>
                      {scan.status}
                    </Badge>
                    {scan.status === 'completed' && (
                      <span className="text-sm font-medium">
                        {scan.findings.critical > 0 && <span className="text-red-500">{scan.findings.critical} crit</span>}
                        {scan.findings.high > 0 && <span className="text-orange-500 ml-1">{scan.findings.high} high</span>}
                        {scan.findings.medium > 0 && <span className="text-yellow-500 ml-1">{scan.findings.medium} med</span>}
                      </span>
                    )}
                    <span className="text-sm text-muted-foreground w-20 text-right">{scan.duration}</span>
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Top Findings */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Top Findings</CardTitle>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/dashboard/findings">View all</Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              {topFindings.map((finding) => (
                <Link key={finding.id} href={`/dashboard/findings/${finding.id}`} className="flex items-center justify-between p-4 hover:bg-accent/50 transition-colors">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className={cn(severityColors[finding.severity])}>
                        {finding.severity}
                      </Badge>
                      <Badge variant="outline" className="bg-muted text-muted-foreground">
                        {finding.layer}
                      </Badge>
                    </div>
                    <p className="font-medium truncate">{finding.title}</p>
                    <p className="text-sm text-muted-foreground">{finding.repo} • {finding.rule}</p>
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
          <Button variant="outline" asChild className="h-auto p-4 flex flex-col items-start gap-2">
            <Link href="/dashboard/projects/new">
              <FolderGit className="h-6 w-6" />
              <span className="font-medium">Create Project</span>
              <span className="text-sm text-muted-foreground">Organize repos into projects</span>
            </Link>
          </Button>
          <Button variant="outline" asChild className="h-auto p-4 flex flex-col items-start gap-2">
            <Link href="/dashboard/reports">
              <FileText className="h-6 w-6" />
              <span className="font-medium">Generate Report</span>
              <span className="text-sm text-muted-foreground">Create executive or technical report</span>
            </Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}