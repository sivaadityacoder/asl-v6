"use client";

import React, { Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { signIn } from "next-auth/react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2, ArrowLeft, Eye, EyeOff, Mail } from "lucide-react";

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const justRegistered = searchParams.get("registered") === "true";
  const callbackUrl = searchParams.get("callbackUrl") || "/dashboard";
  const errorParam = searchParams.get("error");

  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [form, setForm] = useState({ email: "", password: "", otp: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [otpSent, setOtpSent] = useState(false);
  const [loginMethod, setLoginMethod] = useState("password");

  React.useEffect(() => {
    if (justRegistered) {
      toast.success("Account created! Please sign in.");
    }
    if (errorParam === "AccessDenied") {
      toast.error("Access denied. Please contact support.");
    } else if (errorParam === "Verification") {
      toast.error("Email verification required.");
    }
  }, [justRegistered, errorParam]);

  function validateEmail(): boolean {
    if (!form.email.trim()) {
      setErrors({ email: "Email is required" });
      return false;
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) {
      setErrors({ email: "Invalid email format" });
      return false;
    }
    setErrors({});
    return true;
  }

  async function handleSendOTP(e: React.FormEvent) {
    e.preventDefault();
    if (!validateEmail()) return;
    
    setLoading(true);
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${API_URL}/api/v1/auth/otp/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: form.email }),
      });
      
      if (res.ok) {
        setOtpSent(true);
        toast.success("Authentication code sent to your email!");
      } else {
        toast.error("Failed to send code. Please try again.");
      }
    } catch (err) {
      toast.error("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    
    if (!validateEmail()) return;
    
    if (loginMethod === "password" && !form.password) {
      setErrors({ password: "Password is required" });
      return;
    }
    
    if (loginMethod === "otp" && otpSent && !form.otp) {
      setErrors({ otp: "Authentication code is required" });
      return;
    }

    setLoading(true);
    try {
      const signinPayload: Record<string, string> = {
        email: form.email,
        redirect: "false",
      };

      if (loginMethod === "password") {
        signinPayload.password = form.password;
      } else if (loginMethod === "otp") {
        signinPayload.otp = form.otp;
      }

      const result = await signIn("credentials", { ...signinPayload, redirect: false });
      const signInResult = result as { error?: string; ok?: boolean } | undefined;

      if (signInResult?.error) {
        toast.error("Invalid credentials or expired code");
      } else if (signInResult?.ok) {
        toast.success("Welcome back! Redirecting...");
        window.location.href = callbackUrl;
      } else {
        toast.error("Login failed. Please try again.");
      }
    } catch (err) {
      toast.error("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="border-0 shadow-none bg-transparent">
      <CardHeader className="space-y-2 text-center">
        <CardTitle className="text-2xl font-bold tracking-tight">Welcome back</CardTitle>
        <CardDescription>Sign in to your ASL V6 account</CardDescription>
      </CardHeader>
      <CardContent>
        {justRegistered && (
          <div className="mb-4 rounded-lg border border-green-500/30 bg-green-500/10 p-3 text-sm text-green-600">
            ✓ Account created successfully. Please sign in below.
          </div>
        )}
        
        <Tabs defaultValue="password" value={loginMethod} onValueChange={setLoginMethod} className="w-full mb-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="password">Password</TabsTrigger>
            <TabsTrigger value="otp">Magic Link</TabsTrigger>
          </TabsList>
        </Tabs>

        <form onSubmit={loginMethod === "password" || (loginMethod === "otp" && otpSent) ? handleLogin : handleSendOTP} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              placeholder="you@company.com"
              value={form.email}
              onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))}
              disabled={loading || (loginMethod === "otp" && otpSent)}
              autoComplete="email"
            />
            {errors.email && <p className="text-xs text-destructive">{errors.email}</p>}
          </div>

          {loginMethod === "password" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Password</Label>
                <Link href="/forgot-password" className="text-xs text-primary hover:underline">
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  value={form.password}
                  onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))}
                  disabled={loading}
                  autoComplete="current-password"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.password && <p className="text-xs text-destructive">{errors.password}</p>}
            </div>
          )}

          {loginMethod === "otp" && otpSent && (
            <div className="space-y-2 animate-in fade-in slide-in-from-top-2 duration-300">
              <Label htmlFor="otp">Authentication Code</Label>
              <Input
                id="otp"
                type="text"
                placeholder="123456"
                value={form.otp}
                onChange={(e) => setForm((p) => ({ ...p, otp: e.target.value }))}
                disabled={loading}
                autoComplete="one-time-code"
                maxLength={6}
                className="tracking-widest text-center text-lg"
              />
              {errors.otp && <p className="text-xs text-destructive">{errors.otp}</p>}
              <div className="text-xs text-center mt-2 text-muted-foreground">
                Didn't receive a code?{" "}
                <button 
                  type="button" 
                  onClick={() => { setOtpSent(false); setForm(p => ({...p, otp: ""})); }}
                  className="text-primary hover:underline"
                >
                  Try another email
                </button>
              </div>
            </div>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {loginMethod === "otp" && !otpSent ? "Sending..." : "Signing in..."}
              </>
            ) : loginMethod === "otp" && !otpSent ? (
              <>
                <Mail className="mr-2 h-4 w-4" />
                Send Login Code
              </>
            ) : (
              "Sign In"
            )}
          </Button>
        </form>

        <div className="mt-6 text-center text-sm text-muted-foreground">
          Don't have an account?{" "}
          <Link href="/register" className="font-medium text-primary hover:underline">
            Create one
          </Link>
        </div>

        <div className="mt-4">
          <Link
            href="/"
            className="flex items-center justify-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="h-3 w-3" />
            Back to home
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center"><Loader2 className="h-6 w-6 animate-spin" /></div>}>
      <LoginContent />
    </Suspense>
  );
}
