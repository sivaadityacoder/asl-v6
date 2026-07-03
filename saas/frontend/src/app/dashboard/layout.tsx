'use client';

import { Sidebar } from '@/components/dashboard/sidebar';
import { cn } from '@/lib/utils';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <main className={cn('transition-all duration-300', 'lg:ml-64')}>
        <div className="p-6 lg:p-8">
          {children}
        </div>
      </main>
    </div>
  );
}