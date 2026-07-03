// @ts-nocheck
"use client";

import React from "react";
import { motion } from "framer-motion";
import { Activity, ShieldAlert, FileSearch, Code2, AlertTriangle, TerminalSquare } from "lucide-react";

export default function DashboardPreview() {
  return (
    <section className="py-32 relative bg-background overflow-hidden">
      
      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-[600px] bg-primary-DEFAULT/5 blur-[120px] pointer-events-none rounded-full" />

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold tracking-tighter mb-4 font-display">
            Command Center
          </h2>
          <p className="text-lg text-white/50 font-light">
            Monitor risk scores, investigate findings, and remediate vulnerabilities in real-time.
          </p>
        </div>

        {/* Dashboard Mockup Container */}
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
          className="rounded-3xl border border-white/10 bg-[#0B1220]/80 backdrop-blur-2xl shadow-[0_0_80px_rgba(59,130,246,0.15)] overflow-hidden flex flex-col md:flex-row h-[600px]"
        >
          {/* Sidebar */}
          <div className="hidden md:flex w-64 border-r border-white/5 bg-black/40 flex-col p-4">
            <div className="flex items-center gap-2 px-2 py-4 mb-4 border-b border-white/5">
              <ShieldAlert className="w-5 h-5 text-primary-cyan" />
              <span className="font-semibold text-white/90">Acme Corp</span>
            </div>
            <div className="space-y-1">
              {['Overview', 'Findings', 'Repositories', 'Reports', 'Settings'].map((item, i) => (
                <div key={item} className={`px-3 py-2 rounded-lg text-sm font-medium cursor-pointer transition-colors ${i === 0 ? 'bg-primary-DEFAULT/20 text-primary-cyan' : 'text-white/50 hover:bg-white/5 hover:text-white'}`}>
                  {item}
                </div>
              ))}
            </div>
          </div>

          {/* Main Content area */}
          <div className="flex-1 flex flex-col p-6 overflow-hidden">
            <div className="flex justify-between items-center mb-8">
              <div>
                <h3 className="text-xl font-semibold">Security Posture</h3>
                <p className="text-xs text-white/40">Last scanned: 2 minutes ago</p>
              </div>
              <div className="flex gap-3">
                <div className="px-3 py-1.5 rounded-full bg-accent-danger/20 border border-accent-danger/30 text-accent-danger text-xs font-semibold">3 Critical</div>
                <div className="px-3 py-1.5 rounded-full bg-yellow-500/20 border border-yellow-500/30 text-yellow-500 text-xs font-semibold">8 High</div>
              </div>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-3 gap-4 mb-8">
              {[
                { label: 'Platform Risk Score', value: 'D', sub: 'Action Required', color: 'text-accent-danger', icon: AlertTriangle },
                { label: 'Scanned Repos', value: '42', sub: '+3 this week', color: 'text-white', icon: Code2 },
                { label: 'Active Scans', value: '2', sub: 'Running now', color: 'text-primary-cyan', icon: Activity },
              ].map((metric, i) => (
                <div key={i} className="bg-white/[0.02] border border-white/5 rounded-2xl p-4 flex flex-col justify-between h-32 hover:border-white/10 transition-colors">
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-medium text-white/40">{metric.label}</span>
                    <metric.icon className="w-4 h-4 text-white/30" />
                  </div>
                  <div>
                    <span className={`text-3xl font-bold ${metric.color}`}>{metric.value}</span>
                    <p className="text-xs text-white/40 mt-1">{metric.sub}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Findings Table Mockup */}
            <div className="flex-1 bg-white/[0.02] border border-white/5 rounded-2xl overflow-hidden flex flex-col">
              <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-white/5 text-xs font-medium text-white/40 uppercase tracking-wider bg-black/20">
                <div className="col-span-5">Vulnerability</div>
                <div className="col-span-3">Repository</div>
                <div className="col-span-2">Severity</div>
                <div className="col-span-2">Status</div>
              </div>
              <div className="flex-1 overflow-hidden flex flex-col">
                {[
                  { name: 'LLM01: Prompt Injection Bypass', repo: 'customer-support-agent', sev: 'Critical', status: 'Open', icon: TerminalSquare },
                  { name: 'LLM06: Sensitive Information Disclosure', repo: 'hr-resume-parser', sev: 'High', status: 'In Review', icon: FileSearch },
                  { name: 'Hardcoded OpenAI API Key', repo: 'backend-core', sev: 'Critical', status: 'Fixed', icon: Code2 },
                ].map((row, i) => (
                  <div key={i} className="grid grid-cols-12 gap-4 px-6 py-4 border-b border-white/5 text-sm items-center hover:bg-white/[0.02] cursor-pointer transition-colors group">
                    <div className="col-span-5 flex items-center gap-3">
                      <div className="p-1.5 rounded bg-white/5 group-hover:bg-primary-DEFAULT/20 transition-colors">
                        <row.icon className="w-4 h-4 text-white/60 group-hover:text-primary-cyan" />
                      </div>
                      <span className="font-medium text-white/90 truncate">{row.name}</span>
                    </div>
                    <div className="col-span-3 text-white/50 truncate font-mono text-xs">{row.repo}</div>
                    <div className="col-span-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${row.sev === 'Critical' ? 'bg-accent-danger/20 text-accent-danger' : 'bg-yellow-500/20 text-yellow-500'}`}>
                        {row.sev}
                      </span>
                    </div>
                    <div className="col-span-2 text-white/40">{row.status}</div>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </motion.div>
      </div>
    </section>
  );
}
