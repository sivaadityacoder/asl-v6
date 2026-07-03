// @ts-nocheck
"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Shield, ChevronDown, Terminal, Database, Activity, Code2, Lock } from "lucide-react";

const megaMenuFeatures = [
  { icon: Terminal, title: "CLI Tool", desc: "Scan locally in your terminal" },
  { icon: Code2, title: "VS Code Extension", desc: "Real-time IDE feedback" },
  { icon: Activity, title: "CI/CD Integration", desc: "Block vulnerable PRs automatically" },
  { icon: Database, title: "SARIF Export", desc: "Native GitHub Security integration" },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [isMegaMenuOpen, setIsMegaMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <motion.nav
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled 
          ? "bg-background/60 backdrop-blur-2xl border-b border-white/5 py-3 shadow-[0_4px_30px_rgba(0,0,0,0.1)]" 
          : "bg-transparent py-5"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-primary-DEFAULT to-primary-purple shadow-[0_0_20px_rgba(59,130,246,0.3)] border border-white/10 group-hover:shadow-[0_0_25px_rgba(147,51,234,0.4)] transition-all">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-xl font-bold tracking-tighter bg-clip-text text-transparent bg-gradient-to-r from-white to-white/70 font-display">
              ASL V6
            </span>
          </Link>

          <div className="hidden lg:flex items-center gap-8">
            <div 
              className="relative"
              onMouseEnter={() => setIsMegaMenuOpen(true)}
              onMouseLeave={() => setIsMegaMenuOpen(false)}
            >
              <button className="flex items-center gap-1 text-sm font-medium text-white/60 hover:text-white transition-colors py-2">
                Features
                <ChevronDown className={`w-4 h-4 transition-transform duration-300 ${isMegaMenuOpen ? "rotate-180" : ""}`} />
              </button>
              
              <AnimatePresence>
                {isMegaMenuOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    transition={{ duration: 0.2 }}
                    className="absolute top-full left-1/2 -translate-x-1/2 mt-2 w-[500px] bg-card/90 backdrop-blur-3xl border border-white/10 rounded-2xl shadow-[0_0_40px_rgba(0,0,0,0.5)] overflow-hidden"
                  >
                    <div className="p-6 grid grid-cols-2 gap-4">
                      {megaMenuFeatures.map((feat, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 rounded-xl hover:bg-white/[0.03] transition-colors cursor-pointer group">
                          <div className="p-2 bg-primary-DEFAULT/10 rounded-lg group-hover:bg-primary-DEFAULT/20 transition-colors">
                            <feat.icon className="w-5 h-5 text-primary-cyan" />
                          </div>
                          <div>
                            <h4 className="text-sm font-semibold text-white/90 mb-1">{feat.title}</h4>
                            <p className="text-xs text-white/40 leading-relaxed">{feat.desc}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="bg-black/50 p-4 border-t border-white/5 flex justify-between items-center">
                      <div className="flex items-center gap-2 text-xs text-white/50">
                        <Lock className="w-4 h-4" /> Military Grade Encryption
                      </div>
                      <Link href="/docs" className="text-xs font-semibold text-primary-cyan hover:text-primary-DEFAULT transition-colors">
                        View Documentation &rarr;
                      </Link>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
            
            <Link href="#architecture" className="text-sm font-medium text-white/60 hover:text-white transition-colors">Architecture</Link>
            <Link href="/benchmarks" className="text-sm font-medium text-white/60 hover:text-white transition-colors">Benchmarks</Link>
            <Link href="#pricing" className="text-sm font-medium text-white/60 hover:text-white transition-colors">Pricing</Link>
          </div>

          <div className="flex items-center gap-4">
            <Link href="/login">
              <Button variant="ghost" className="text-white/70 hover:text-white hover:bg-white/5 h-10 px-5 rounded-full text-sm font-medium transition-colors">
                Sign In
              </Button>
            </Link>
            <Link href="/register">
              <Button className="bg-white text-black hover:bg-white/90 h-10 px-6 rounded-full text-sm font-medium shadow-[0_0_20px_rgba(255,255,255,0.15)] transition-all hover:scale-105 hover:shadow-[0_0_30px_rgba(255,255,255,0.3)]">
                Get Started
              </Button>
            </Link>
          </div>
        </div>
      </div>
    </motion.nav>
  );
}
