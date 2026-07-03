// @ts-nocheck
"use client";

import React, { useRef } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import { Github, Download, Search, PlayCircle, Filter, FileText, Wrench } from "lucide-react";

const steps = [
  { icon: Github, title: "Connect", desc: "Integrate via GitHub App in 2 clicks" },
  { icon: Download, title: "Clone", desc: "Securely clone into ephemeral sandbox" },
  { icon: Search, title: "Scan", desc: "10-layer static & context analysis" },
  { icon: PlayCircle, title: "Validate", desc: "DAST execution on active endpoints" },
  { icon: Filter, title: "Prioritize", desc: "AI-assisted triage filters false positives" },
  { icon: FileText, title: "Report", desc: "SARIF generation for CI/CD" },
  { icon: Wrench, title: "Fix", desc: "Automated PRs with secure code" },
];

export default function HowItWorks() {
  const containerRef = useRef(null);
  const { scrollYProgress } = useScroll({
    target: containerRef as any,
    offset: ["start center", "end center"],
  });

  return (
    <section className="py-32 relative bg-[#02040A] overflow-hidden" ref={containerRef}>
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(34,211,238,0.05),transparent_70%)]" />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center mb-24">
          <h2 className="text-4xl md:text-5xl font-bold tracking-tighter mb-4 font-display">
            How ASL Works
          </h2>
          <p className="text-xl text-white/50 font-light">From connection to remediation in under 3 minutes.</p>
        </div>

        <div className="flex flex-col md:flex-row justify-between items-center relative">
          {/* Connecting Line */}
          <div className="absolute top-1/2 left-0 w-full h-[2px] bg-white/5 -translate-y-1/2 hidden md:block" />
          
          {/* Animated Progress Line */}
          <motion.div 
            className="absolute top-1/2 left-0 h-[2px] bg-gradient-to-r from-primary-cyan to-primary-purple -translate-y-1/2 hidden md:block"
            style={{ width: useTransform(scrollYProgress, [0, 1], ["0%", "100%"]) }}
          />

          {steps.map((step, i) => (
            <div key={i} className="relative z-10 flex flex-col items-center group w-full md:w-auto mb-12 md:mb-0">
              <motion.div 
                whileHover={{ scale: 1.1, y: -5 }}
                className="w-16 h-16 rounded-2xl bg-card border border-white/10 flex items-center justify-center mb-4 shadow-lg group-hover:border-primary-cyan/50 group-hover:shadow-[0_0_20px_rgba(34,211,238,0.3)] transition-all bg-background"
              >
                <step.icon className="w-6 h-6 text-white/70 group-hover:text-primary-cyan transition-colors" />
              </motion.div>
              <h3 className="text-lg font-semibold text-white/90 mb-2">{step.title}</h3>
              <p className="text-xs text-center text-white/40 max-w-[120px] font-light leading-relaxed">{step.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
