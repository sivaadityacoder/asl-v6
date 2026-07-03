// @ts-nocheck
"use client";

import React from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { ArrowRight, ShieldCheck } from "lucide-react";
import Link from "next/link";

export default function HeroSection() {
  return (
    <section className="relative min-h-[90vh] flex flex-col items-center justify-center pt-32 pb-20 overflow-hidden">
      {/* Animated Aurora Background */}
      <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
        <motion.div
          animate={{
            transform: ["translateY(0px) rotate(0deg)", "translateY(-50px) rotate(5deg)", "translateY(0px) rotate(0deg)"],
          }}
          transition={{ duration: 15, repeat: Infinity, ease: "easeInOut" }}
          className="absolute -top-[20%] -left-[10%] w-[70%] h-[70%] bg-primary-purple/20 blur-[150px] rounded-full mix-blend-screen"
        />
        <motion.div
          animate={{
            transform: ["translateY(0px) rotate(0deg)", "translateY(30px) rotate(-5deg)", "translateY(0px) rotate(0deg)"],
          }}
          transition={{ duration: 20, repeat: Infinity, ease: "easeInOut", delay: 2 }}
          className="absolute top-[10%] -right-[10%] w-[60%] h-[60%] bg-primary-cyan/15 blur-[150px] rounded-full mix-blend-screen"
        />
        <div className="absolute inset-0 bg-cyber-grid opacity-20 [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center flex flex-col items-center">
        {/* Animated Trust Badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/[0.03] border border-white/10 backdrop-blur-xl mb-12 shadow-[0_0_30px_rgba(34,211,238,0.1)] hover:border-primary-cyan/30 transition-colors cursor-pointer"
        >
          <ShieldCheck className="w-4 h-4 text-primary-cyan" />
          <span className="text-sm font-medium tracking-wide text-white/80">ASL V6 Platform Now Available</span>
        </motion.div>

        {/* Cinematic Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1, delay: 0.4, ease: [0.16, 1, 0.3, 1] }}
          className="text-7xl md:text-[7rem] font-extrabold tracking-tighter leading-[0.95] mb-8 font-display"
        >
          Secure the <br className="hidden md:block" />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary-purple via-primary-DEFAULT to-primary-cyan animate-aurora-pan bg-[length:200%_auto]">
            Future of AI.
          </span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="text-xl md:text-2xl text-white/50 max-w-3xl mb-12 font-light text-balance leading-relaxed"
        >
          ASL V6 continuously discovers, validates, and prioritizes security risks across modern AI applications. 
          Stop prompt injections and data poisoning before they reach production.
        </motion.p>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.8 }}
          className="flex flex-col sm:flex-row items-center gap-6"
        >
          <Link href="/register">
            <Button size="lg" className="h-16 px-10 rounded-full bg-white text-black hover:bg-white/90 text-lg font-semibold shadow-[0_0_40px_rgba(255,255,255,0.2)] transition-all hover:scale-105">
              Request Private Beta
              <ArrowRight className="ml-2 w-5 h-5" />
            </Button>
          </Link>
          <Link href="#architecture">
            <Button size="lg" variant="outline" className="h-16 px-10 rounded-full border-white/10 bg-white/[0.02] hover:bg-white/[0.05] text-white text-lg font-medium backdrop-blur-md transition-all">
              Watch Architecture
            </Button>
          </Link>
        </motion.div>
      </div>
      
      {/* 3D Floating Element Overlay at the bottom */}
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5, duration: 2 }}
        className="absolute bottom-0 w-full h-32 bg-gradient-to-t from-background to-transparent z-20 pointer-events-none" 
      />
    </section>
  );
}
