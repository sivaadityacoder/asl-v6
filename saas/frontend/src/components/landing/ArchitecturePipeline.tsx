// @ts-nocheck
"use client";

import React, { useRef, useState, useEffect } from "react";
import { motion, useScroll, useTransform, useSpring } from "framer-motion";
import { 
  Github, Search, Code, Key, GitMerge, FileCode2, 
  ShieldAlert, Target, PlayCircle, Brain, FileOutput 
} from "lucide-react";

const pipelineNodes = [
  { id: "github", label: "GitHub Webhook", icon: Github, color: "text-white" },
  { id: "discovery", label: "Repository Discovery", icon: Search, color: "text-primary-cyan" },
  { id: "static", label: "Static Analysis (SAST)", icon: Code, color: "text-primary-purple" },
  { id: "secrets", label: "Secrets Scanning", icon: Key, color: "text-primary-DEFAULT" },
  { id: "reachability", label: "Reachability Analysis", icon: GitMerge, color: "text-accent-emerald" },
  { id: "context", label: "Contextual Pattern Matching", icon: FileCode2, color: "text-primary-cyan" },
  { id: "owasp", label: "OWASP LLM Top 10", icon: ShieldAlert, color: "text-accent-danger" },
  { id: "mitre", label: "MITRE ATLAS Mapping", icon: Target, color: "text-primary-purple" },
  { id: "dynamic", label: "Dynamic Validation (DAST)", icon: PlayCircle, color: "text-primary-DEFAULT" },
  { id: "ai", label: "AI-Powered Security Review", icon: Brain, color: "text-accent-emerald" },
  { id: "report", label: "Security Report (SARIF/PDF)", icon: FileOutput, color: "text-white" },
];

export default function ArchitecturePipeline() {
  const [mounted, setMounted] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  
  const { scrollYProgress } = useScroll({ 
    target: containerRef as any, 
    offset: ["start center", "end center"] 
  });
  
  // Smooth out the scroll progress for the laser beam
  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001
  });

  const laserHeight = useTransform(smoothProgress, [0, 1], ["0%", "100%"]);

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <section className="py-32 relative bg-[#02040A] border-t border-white/5" ref={containerRef as any}>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        <div className="text-center mb-24">
          <h2 className="text-3xl md:text-5xl font-bold tracking-tighter mb-4 font-display">
            The 10-Layer Architecture
          </h2>
          <p className="text-lg text-white/50 font-light max-w-2xl mx-auto">
            Code flows through a specialized gauntlet of static, dynamic, and AI-driven analysis engines designed exclusively for GenAI.
          </p>
        </div>

        <div className="relative pb-10">
          {/* Static Background Track */}
          <div className="absolute left-8 md:left-1/2 top-10 bottom-10 w-px bg-white/10 -translate-x-1/2" />
          
          {/* Animated Data Flow Laser Beam */}
          {mounted && (
            <motion.div 
              className="absolute left-8 md:left-1/2 top-10 w-[3px] bg-gradient-to-b from-primary-cyan via-primary-purple to-primary-DEFAULT -translate-x-1/2 rounded-full shadow-[0_0_30px_rgba(147,51,234,1)] origin-top"
              style={{ height: laserHeight }}
            />
          )}

          <div className="space-y-12">
            {pipelineNodes.map((node, i) => {
              // Calculate activation threshold for this specific node based on its index
              const threshold = i / (pipelineNodes.length - 1);
              
              return (
                <PipelineNode 
                  key={node.id} 
                  node={node} 
                  index={i} 
                  progress={smoothProgress} 
                  threshold={threshold}
                />
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}

function PipelineNode({ node, index, progress, threshold }: any) {
  // Animate node opacity and scale when the laser beam reaches it
  const opacity = useTransform(progress, [threshold - 0.1, threshold], [0.3, 1]);
  const scale = useTransform(progress, [threshold - 0.1, threshold], [0.9, 1.05]);
  const borderColor = useTransform(
    progress, 
    [threshold - 0.1, threshold], 
    ["rgba(255,255,255,0.1)", "rgba(147,51,234,0.5)"]
  );
  const boxShadow = useTransform(
    progress, 
    [threshold - 0.1, threshold], 
    ["0 0 0px rgba(147,51,234,0)", "0 0 30px rgba(147,51,234,0.3)"]
  );

  const isLeft = index % 2 === 0;

  return (
    <div className={`relative flex items-center ${isLeft ? 'md:flex-row' : 'md:flex-row-reverse'}`}>
      
      {/* Center Icon Node */}
      <motion.div 
        style={{ opacity, scale, borderColor, boxShadow }}
        className="absolute left-8 md:left-1/2 w-14 h-14 bg-card border rounded-2xl flex items-center justify-center -translate-x-1/2 z-10"
      >
        <node.icon className={`w-6 h-6 ${node.color}`} />
      </motion.div>

      {/* Label Box */}
      <div className={`w-full pl-24 md:pl-0 md:w-1/2 ${isLeft ? 'md:pr-20 text-left md:text-right' : 'md:pl-20 text-left'}`}>
        <motion.div 
          style={{ opacity, y: useTransform(progress, [threshold - 0.1, threshold], [10, 0]) }}
          className="inline-block py-3 px-6 rounded-2xl bg-white/[0.02] border border-white/5 backdrop-blur-sm"
        >
          <span className="text-lg font-medium text-white/90 tracking-tight">{node.label}</span>
        </motion.div>
      </div>
    </div>
  );
}
