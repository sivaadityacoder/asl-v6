import Link from "next/link";
import { Shield } from "lucide-react";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background px-4 py-12">
      {/* Logo */}
      <Link href="/" className="flex items-center gap-2 mb-8">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-primary-DEFAULT to-primary-purple border border-white/10 shadow-[0_0_20px_rgba(59,130,246,0.3)]">
          <Shield className="h-5 w-5 text-white" />
        </div>
        <span className="text-xl font-bold tracking-tighter font-display">ASL V6</span>
      </Link>

      {/* Card container */}
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-card p-8 shadow-xl">
        {children}
      </div>

      <p className="mt-8 text-xs text-muted-foreground text-center">
        © 2026 Aditya Security Labs. All rights reserved.
      </p>
    </div>
  );
}
