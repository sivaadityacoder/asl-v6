// @ts-nocheck
"use client";

import React from "react";
import { motion } from "framer-motion";
import { Terminal, Code2, GitPullRequest, FileCode, ArrowRight } from "lucide-react";
import Link from "next/link";

const features = [
  {
    title: "CLI Tool",
    description: "Scan AI applications directly from your terminal with a single command. Integrate ASL V6 into local development workflows for fast security validation before every commit.",
    icon: Terminal,
    cta: "Learn More",
    link: "#",
    badge: null,
    extra: (
      <div className="mt-6 p-3 rounded-xl bg-black/60 border border-white/10 font-mono text-xs text-white/70 flex items-center gap-2">
        <span className="text-primary-cyan">❯</span>
        <span>asl scan ./project --deep</span>
      </div>
    ),
  },
  {
    title: "VS Code Extension",
    description: "Detect AI security risks while coding with real-time diagnostics, inline explanations, and remediation guidance directly inside Visual Studio Code.",
    icon: Code2,
    cta: "Coming Soon",
    link: "#",
    badge: "Beta",
    extra: null,
  },
  {
    title: "CI/CD Integration",
    description: "Automatically scan every pull request and build pipeline. Fail builds only when validated, high-confidence security risks are detected.",
    icon: GitPullRequest,
    cta: "View Integrations",
    link: "#",
    badge: null,
    extra: (
      <div className="mt-6 flex flex-wrap gap-2">
        {["GitHub Actions", "GitLab CI", "Jenkins", "Azure DevOps"].map((item) => (
          <span key={item} className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-[10px] uppercase tracking-wider text-white/50 font-semibold">
            {item}
          </span>
        ))}
      </div>
    ),
  },
  {
    title: "SARIF Export",
    description: "Export findings in SARIF format for seamless integration with GitHub Advanced Security and enterprise security workflows.",
    icon: FileCode,
    cta: "Documentation",
    link: "#",
    badge: null,
    extra: (
      <div className="mt-6 flex flex-wrap gap-2">
        {["SARIF 2.1.0", "PDF Reports", "JSON", "CSV"].map((item) => (
          <span key={item} className="px-2.5 py-1 rounded-md bg-white/5 border border-white/10 text-[10px] uppercase tracking-wider text-white/50 font-semibold">
            {item}
          </span>
        ))}
      </div>
    ),
  },
];

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.15 },
  },
};

const cardVariants = {
  hidden: { opacity: 0, y: 30 },
  show: { 
    opacity: 1, 
    y: 0,
    transition: { type: "spring", stiffness: 50, damping: 15 }
  },
};

export default function DeveloperExperience() {
  return (
    <section className="py-32 bg-[#02040A] relative overflow-hidden">
      {/* Background ambient lighting */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary-cyan/5 blur-[150px] rounded-full pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-primary-purple/5 blur-[150px] rounded-full pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        <div className="text-center mb-20 max-w-3xl mx-auto">
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-DEFAULT/10 border border-primary-DEFAULT/20 text-primary-cyan text-xs font-semibold uppercase tracking-widest mb-6"
          >
            Developer Experience
          </motion.div>
          <motion.h2 
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="text-4xl md:text-5xl font-bold tracking-tighter mb-6 font-display"
          >
            Built for the <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary-cyan to-primary-purple">engineering workflow.</span>
          </motion.h2>
          <motion.p 
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
            className="text-lg text-white/50 font-light"
          >
            Security should never slow down development. ASL V6 integrates natively into your existing tools, providing real-time feedback without the friction.
          </motion.p>
        </div>

        <motion.div 
          variants={containerVariants}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-100px" }}
          className="grid grid-cols-1 md:grid-cols-2 gap-6"
        >
          {features.map((feature, i) => (
            <motion.div 
              key={i} 
              variants={cardVariants}
              className="group relative p-8 rounded-3xl bg-card border border-white/5 hover:border-primary-cyan/30 transition-all duration-500 overflow-hidden"
            >
              {/* Hover gradient background */}
              <div className="absolute inset-0 bg-gradient-to-br from-primary-cyan/0 via-primary-cyan/0 to-primary-cyan/5 opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none" />
              
              <div className="relative z-10 h-full flex flex-col">
                <div className="flex justify-between items-start mb-6">
                  <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-white/5 to-white/[0.01] border border-white/10 flex items-center justify-center group-hover:bg-primary-cyan/10 group-hover:border-primary-cyan/20 group-hover:scale-110 transition-all duration-500">
                    <feature.icon className="w-7 h-7 text-white/70 group-hover:text-primary-cyan transition-colors" />
                  </div>
                  {feature.badge && (
                    <span className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-xs font-medium text-white/60">
                      {feature.badge}
                    </span>
                  )}
                </div>
                
                <h3 className="text-2xl font-bold tracking-tight text-white/90 mb-3">{feature.title}</h3>
                <p className="text-white/40 font-light leading-relaxed flex-1">{feature.description}</p>
                
                {feature.extra}
                
                <div className="mt-8 pt-6 border-t border-white/5">
                  <Link href={feature.link} className="inline-flex items-center gap-2 text-sm font-semibold text-white/60 group-hover:text-primary-cyan transition-colors">
                    {feature.cta} <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                  </Link>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
