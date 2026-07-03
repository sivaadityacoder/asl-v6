"use client";

import React from "react";
import Link from "next/link";
import Navbar from "@/components/landing/Navbar";
import HeroSection from "@/components/landing/HeroSection";
import AnimatedTerminal from "@/components/landing/AnimatedTerminal";
import ArchitecturePipeline from "@/components/landing/ArchitecturePipeline";
import DashboardPreview from "@/components/landing/DashboardPreview";
import DeveloperExperience from "@/components/landing/DeveloperExperience";
import HowItWorks from "@/components/landing/HowItWorks";
import Benchmarks from "@/components/landing/Benchmarks";
import Integrations from "@/components/landing/Integrations";
import Security from "@/components/landing/Security";
import FAQ from "@/components/landing/FAQ";
import { Shield, Brain, GitBranch, Target, Search, FileCode2, CheckCircle2, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";

const features = [
  { icon: Shield, title: "OWASP LLM Top 10", desc: "Comprehensive detection of LLM01-LLM10 vulnerabilities including prompt injection." },
  { icon: Target, title: "MITRE ATLAS Mapping", desc: "16 tactics and 84+ techniques mapped to findings for advanced threat intelligence." },
  { icon: GitBranch, title: "Native GitHub Integration", desc: "Connect repositories, auto-scan on push, and block vulnerable PRs instantly." },
  { icon: Brain, title: "AI-Powered Triage", desc: "Compatible with NVIDIA-hosted models to dramatically reduce false positives and suggest remediation." },
  { icon: Search, title: "Reachability Analysis", desc: "Advanced attack path tracing to see if a vulnerability is actually exploitable." },
  { icon: FileCode2, title: "SARIF & PDF Reports", desc: "Generate executive summaries and developer-friendly artifact formats automatically." },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-foreground font-sans selection:bg-primary-DEFAULT/30">
      <Navbar />
      
      <main>
        <HeroSection />
        
        {/* Trust Section - No Fake Logos */}
        <section className="py-12 border-y border-white/5 bg-white/[0.01] overflow-hidden">
          <div className="max-w-7xl mx-auto px-4">
            <div className="flex flex-col md:flex-row justify-center items-center gap-8 md:gap-16 text-lg md:text-xl font-medium tracking-wide text-white/50">
              <span className="flex items-center gap-3"><Shield className="w-5 h-5 text-primary-cyan/70" /> Built for AI Startups</span>
              <span className="hidden md:block w-1.5 h-1.5 rounded-full bg-white/10" />
              <span className="flex items-center gap-3"><Target className="w-5 h-5 text-primary-purple/70" /> Built for Security Teams</span>
              <span className="hidden md:block w-1.5 h-1.5 rounded-full bg-white/10" />
              <span className="flex items-center gap-3"><Brain className="w-5 h-5 text-primary-DEFAULT/70" /> Built for Enterprise AI</span>
            </div>
          </div>
        </section>

        <AnimatedTerminal />
        <HowItWorks />
        <ArchitecturePipeline />
        <DashboardPreview />
        <DeveloperExperience />

        {/* Features Bento Grid */}
        <section id="features" className="py-32 relative bg-black">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
            <div className="text-center mb-20">
              <h2 className="text-4xl md:text-6xl font-bold tracking-tighter mb-6 font-display">
                Everything you need to <br/> secure GenAI.
              </h2>
            </div>
            
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {features.map((feature, i) => (
                <div key={i} className="group p-8 rounded-3xl bg-card border border-white/5 hover:border-primary-cyan/30 hover:bg-card-hover transition-all duration-500 hover:-translate-y-1 shadow-lg hover:shadow-[0_0_40px_rgba(34,211,238,0.1)]">
                  <div className="w-12 h-12 rounded-2xl bg-white/[0.03] border border-white/10 flex items-center justify-center mb-6 group-hover:bg-primary-cyan/10 group-hover:border-primary-cyan/20 transition-colors">
                    <feature.icon className="w-6 h-6 text-primary-cyan" />
                  </div>
                  <h3 className="text-xl font-semibold mb-3 text-white/90 tracking-tight">{feature.title}</h3>
                  <p className="text-white/40 font-light leading-relaxed">{feature.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <Benchmarks />
        <Integrations />
        <Security />

        {/* Ultra Premium Pricing */}
        <section id="pricing" className="py-32 relative border-t border-white/5 bg-[#02040A]">
          <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
            <div className="text-center mb-20">
              <h2 className="text-4xl md:text-5xl font-bold tracking-tighter mb-6 font-display">Scale securely.</h2>
            </div>

            <div className="grid md:grid-cols-2 gap-8">
              {/* Pro Tier */}
              <div className="p-10 rounded-[2.5rem] bg-card border border-white/5 hover:border-primary-cyan/20 transition-all duration-500 flex flex-col relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-64 h-64 bg-primary-cyan/5 blur-[100px] rounded-full group-hover:bg-primary-cyan/10 transition-colors" />
                <h3 className="text-2xl font-bold tracking-tight mb-2">Pro</h3>
                <p className="text-white/40 mb-8 font-light">For growing teams building AI agents.</p>
                <div className="mb-8">
                  <span className="text-6xl font-extrabold tracking-tighter">$199</span>
                  <span className="text-white/40">/mo</span>
                </div>
                <Button className="w-full h-14 rounded-full bg-white text-black hover:bg-white/90 font-semibold mb-10 text-base shadow-[0_0_20px_rgba(255,255,255,0.1)]">Start 14-Day Free Trial</Button>
                <ul className="space-y-4 flex-1">
                  {['25 Repositories', '500 Scans / month', 'OWASP LLM & MITRE mapping', 'GitHub CI/CD Integration', 'SARIF & PDF Reports'].map((feat, i) => (
                    <li key={i} className="flex items-center gap-4 text-white/60 font-light">
                      <CheckCircle2 className="w-5 h-5 text-primary-cyan" /> {feat}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Enterprise Tier */}
              <div className="p-10 rounded-[2.5rem] bg-gradient-to-b from-card-hover to-card border border-primary-purple/30 transition-all duration-500 flex flex-col relative overflow-hidden shadow-[0_0_50px_rgba(147,51,234,0.15)]">
                <div className="absolute top-0 right-0 w-64 h-64 bg-primary-purple/20 blur-[100px] rounded-full" />
                <div className="absolute -top-3 left-8 px-4 py-1 bg-gradient-to-r from-primary-DEFAULT to-primary-purple rounded-full text-[10px] font-bold tracking-widest uppercase shadow-[0_0_20px_rgba(147,51,234,0.5)]">
                  Enterprise
                </div>
                <h3 className="text-2xl font-bold tracking-tight mb-2 mt-4">Platform</h3>
                <p className="text-primary-cyan/80 mb-8 font-light">Unlimited security for massive scale.</p>
                <div className="mb-8">
                  <span className="text-6xl font-extrabold tracking-tighter">Custom</span>
                </div>
                <Button className="w-full h-14 rounded-full bg-gradient-to-r from-primary-DEFAULT to-primary-purple text-white hover:opacity-90 font-semibold mb-10 text-base shadow-[0_0_30px_rgba(147,51,234,0.3)]">Contact Sales</Button>
                <ul className="space-y-4 flex-1">
                  {['Unlimited Repositories', 'Unlimited Scans', 'Dedicated AI Review Node', 'On-Premise / VPC Deployment', 'Custom Security Policies', '24/7 Priority Support'].map((feat, i) => (
                    <li key={i} className="flex items-center gap-4 text-white/80 font-medium">
                      <CheckCircle2 className="w-5 h-5 text-primary-purple" /> {feat}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>

        <FAQ />

        {/* Ultra Minimal Footer */}
        <footer className="py-12 border-t border-white/5 bg-black">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-6">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary-cyan" />
              <span className="font-bold tracking-tighter font-display text-lg">ASL V6</span>
            </div>
            <div className="flex gap-8 text-sm text-white/40 font-light">
              <Link href="/docs" className="hover:text-white transition-colors">Documentation</Link>
              <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">Twitter</a>
              <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">GitHub</a>
              <Link href="/privacy" className="hover:text-white transition-colors">Privacy</Link>
            </div>
            <div className="text-xs text-white/30 font-light">
              © 2026 Aditya Security Labs.
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}