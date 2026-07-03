// @ts-nocheck
"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Terminal, CheckCircle2, ShieldAlert, Cpu } from "lucide-react";

const scanSequence = [
  { text: "Initializing ASL V6 Engine...", type: "system", delay: 500 },
  { text: "Cloning repository: acme-corp/llm-agent...", type: "action", delay: 1000 },
  { text: "Running Contextual Analysis (Layer 5)...", type: "action", delay: 2000 },
  { text: "Identified Anthropic Claude 3.5 Sonnet endpoints", type: "info", delay: 2500 },
  { text: "Executing Dynamic Validation (Layer 8)...", type: "action", delay: 3500 },
  { text: "[CRITICAL] Prompt Injection Vulnerability Found (LLM01)", type: "alert", delay: 5000 },
  { text: "Evidence: User input bypasses system prompt via encoded payload", type: "info", delay: 5500 },
  { text: "AI-Assisted Security Review: True Positive (Confidence: 99.8%)", type: "system", delay: 7000 },
  { text: "Generating SARIF Report...", type: "action", delay: 8000 },
  { text: "Scan Complete. 1 Critical, 0 High, 2 Medium.", type: "success", delay: 9000 },
];

export default function AnimatedTerminal() {
  const [lines, setLines] = useState<number[]>([]);

  useEffect(() => {
    let timeouts: NodeJS.Timeout[] = [];
    
    const startSequence = () => {
      setLines([]);
      scanSequence.forEach((_, i) => {
        const timeout = setTimeout(() => {
          setLines((prev) => [...prev, i]);
        }, scanSequence[i].delay);
        timeouts.push(timeout);
      });
    };

    startSequence();

    // Restart sequence every 15 seconds
    const loop = setInterval(startSequence, 15000);

    return () => {
      timeouts.forEach(clearTimeout);
      clearInterval(loop);
    };
  }, []);

  const renderLineIcon = (type: string) => {
    switch (type) {
      case "system": return <Cpu className="w-4 h-4 text-primary-purple" />;
      case "alert": return <ShieldAlert className="w-4 h-4 text-accent-danger animate-pulse" />;
      case "success": return <CheckCircle2 className="w-4 h-4 text-accent-emerald" />;
      case "info": return <span className="text-primary-cyan opacity-50">ℹ</span>;
      default: return <span className="text-white/30">❯</span>;
    }
  };

  const renderLineColor = (type: string) => {
    switch (type) {
      case "alert": return "text-accent-danger font-semibold";
      case "success": return "text-accent-emerald font-semibold";
      case "system": return "text-primary-purple";
      case "info": return "text-primary-cyan/80";
      default: return "text-white/70";
    }
  };

  return (
    <section className="py-24 relative overflow-hidden">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold tracking-tighter mb-4 font-display">
            Real-time Threat Execution
          </h2>
          <p className="text-lg text-white/50 font-light">
            Watch the ASL V6 engine identify and validate a zero-day prompt injection in seconds.
          </p>
        </div>

        {/* Terminal Window */}
        <motion.div 
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="relative rounded-2xl bg-[#030509] border border-white/10 shadow-[0_0_50px_rgba(0,0,0,0.5)] overflow-hidden"
        >
          {/* Mac Window Controls */}
          <div className="flex items-center gap-2 px-4 py-3 bg-[#0a0f1a] border-b border-white/5">
            <div className="w-3 h-3 rounded-full bg-accent-danger/80" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <div className="w-3 h-3 rounded-full bg-accent-emerald/80" />
            <div className="ml-4 flex items-center gap-2 text-xs text-white/40 font-mono">
              <Terminal className="w-3.5 h-3.5" />
              asl-scan --target ./acme-corp --deep
            </div>
          </div>

          {/* Terminal Content */}
          <div className="p-6 font-mono text-sm min-h-[400px] flex flex-col gap-3 relative">
            
            {/* Subtle glow behind the terminal text */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[80%] h-[80%] bg-primary-DEFAULT/5 blur-[100px] pointer-events-none rounded-full" />

            <AnimatePresence>
              {lines.map((index) => {
                const line = scanSequence[index];
                return (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="flex items-start gap-3 relative z-10"
                  >
                    <div className="mt-0.5 w-4 flex-shrink-0 flex justify-center">
                      {renderLineIcon(line.type)}
                    </div>
                    <div className={`${renderLineColor(line.type)} tracking-wide leading-relaxed`}>
                      {line.text}
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>

            {/* Blinking Cursor */}
            <motion.div 
              animate={{ opacity: [1, 0, 1] }}
              transition={{ repeat: Infinity, duration: 0.8 }}
              className="w-2.5 h-5 bg-primary-cyan/60 ml-7 mt-1"
            />
          </div>
        </motion.div>
      </div>
    </section>
  );
}
