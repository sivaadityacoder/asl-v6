"use client";

import React from "react";
import { motion } from "framer-motion";

const integrations = [
  "GitHub", "GitLab", "Docker", "Supabase", 
  "PostgreSQL", "NVIDIA", "Ollama", "FastAPI", 
  "Slack", "Jira", "Vercel", "Fly.io"
];

export default function Integrations() {
  return (
    <section className="py-24 bg-[#02040A] border-t border-white/5 overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center mb-16">
        <h2 className="text-3xl font-bold tracking-tighter mb-4 font-display">Seamless Integrations</h2>
        <p className="text-white/50 font-light text-sm max-w-xl mx-auto">
          ASL V6 plugs directly into your existing AI engineering stack.
        </p>
      </div>

      <div className="relative flex overflow-x-hidden group">
        <div className="absolute top-0 left-0 w-32 h-full bg-gradient-to-r from-[#02040A] to-transparent z-10" />
        <div className="absolute top-0 right-0 w-32 h-full bg-gradient-to-l from-[#02040A] to-transparent z-10" />
        
        <div className="py-4 animate-scroll-left whitespace-nowrap flex gap-8 items-center px-4">
          {[...integrations, ...integrations].map((item, i) => (
            <div 
              key={i} 
              className="px-6 py-3 rounded-full bg-white/[0.02] border border-white/5 text-white/60 font-medium tracking-wide hover:text-white hover:border-white/20 transition-colors inline-block"
            >
              {item}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
