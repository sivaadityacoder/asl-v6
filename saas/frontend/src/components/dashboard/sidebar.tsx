'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useSession, signOut } from 'next-auth/react';
import { toast } from 'sonner';
import { 
  LayoutDashboard, 
  FolderGit, 
  GitBranch, 
  PlayCircle, 
  Activity, 
  FileText, 
  Settings, 
  CreditCard,
  Shield,
  LogOut,
  ChevronDown,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Projects', href: '/dashboard/projects', icon: FolderGit },
  { name: 'Repositories', href: '/dashboard/repositories', icon: GitBranch },
  { name: 'Scans', href: '/dashboard/scans', icon: PlayCircle },
  { name: 'Live Scan', href: '/dashboard/live', icon: Activity },
  { name: 'Findings', href: '/dashboard/findings', icon: Shield },
  { name: 'Reports', href: '/dashboard/reports', icon: FileText },
  { name: 'Billing', href: '/dashboard/billing', icon: CreditCard },
  { name: 'Settings', href: '/dashboard/settings', icon: Settings },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const pathname = usePathname();
  const router = useRouter();
  const { data: session } = useSession();

  const userName = session?.user?.name || session?.user?.email || 'User';
  const userEmail = session?.user?.email || 'user@company.com';
  const userImage = session?.user?.image;
  const userInitial = (session?.user?.name || session?.user?.email || 'U').charAt(0).toUpperCase();

  async function handleLogout() {
    try {
      // Optionally call backend logout to invalidate server-side state
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const token = session?.access_token;
      if (token) {
        await fetch(`${API_URL}/api/v1/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        }).catch(() => {});
      }
      await signOut({ redirect: false, callbackUrl: "/login" });
      toast.success("Signed out successfully");
      router.push("/login");
      router.refresh();
    } catch (err) {
      toast.error("Failed to sign out");
      // Force redirect anyway
      router.push("/login");
    }
  }

  return (
    <aside className={cn(
      'fixed left-0 top-0 z-40 h-screen bg-card border-r border-border transition-all duration-300',
      collapsed ? 'w-16' : 'w-64'
    )}>
      <div className="flex h-full flex-col">
        {/* Logo */}
        <div className={cn('flex h-16 items-center justify-between px-4 border-b border-border', collapsed && 'justify-center')}>
          <Link href="/dashboard" className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            {!collapsed && <span className="text-xl font-bold">ASL V6</span>}
          </Link>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronDown className="h-4 w-4 rotate-180" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
          {navigation.map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
            return (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                  collapsed && 'justify-center'
                )}
                title={collapsed ? item.name : undefined}
              >
                <item.icon className="h-5 w-5 flex-shrink-0" />
                {!collapsed && <span>{item.name}</span>}
              </Link>
            );
          })}
        </nav>

        {/* User Section */}
        <div className="p-4 border-t border-border">
          {!collapsed ? (
            <div className="flex items-center gap-3">
              <Avatar className="h-9 w-9">
                {userImage ? <AvatarImage src={userImage} alt={userName} /> : null}
                <AvatarFallback>{userInitial}</AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{userName}</p>
                <p className="text-xs text-muted-foreground truncate">{userEmail}</p>
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8">
                    <ChevronDown className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <DropdownMenuItem asChild>
                    <Link href="/dashboard/settings" className="flex items-center gap-2">
                      <Settings className="h-4 w-4" />
                      Settings
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem asChild>
                    <Link href="/dashboard/billing" className="flex items-center gap-2">
                      <CreditCard className="h-4 w-4" />
                      Billing
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem className="text-destructive flex items-center gap-2" onClick={handleLogout}>
                    <LogOut className="h-4 w-4" />
                    Log out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          ) : (
            <div className="flex justify-center">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Avatar className="h-9 w-9">
                    {userImage ? <AvatarImage src={userImage} alt={userName} /> : null}
                    <AvatarFallback>{userInitial}</AvatarFallback>
                  </Avatar>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <DropdownMenuItem asChild>
                    <Link href="/dashboard/settings" className="flex items-center gap-2">
                      <Settings className="h-4 w-4" />
                      Settings
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem asChild>
                    <Link href="/dashboard/billing" className="flex items-center gap-2">
                      <CreditCard className="h-4 w-4" />
                      Billing
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem className="text-destructive flex items-center gap-2" onClick={handleLogout}>
                    <LogOut className="h-4 w-4" />
                    Log out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
