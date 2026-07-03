// @ts-nocheck
"use client";

import React from "react";
import { Check, X, Minus } from "lucide-react";
import { motion } from "framer-motion";

const features = [
  "Reachability Analysis",
  "Dynamic Validation",
  "AI Review (False Positives)",
  "OWASP LLM Top 10",
  "MITRE ATLAS",
  "GitHub Native Integration",
  "PoC Evidence Generation",
  "SARIF Export",
];

const competitors = [
  { name: "Legacy SAST", matches: [false, false, false, false, false, false, false, true] },
  { name: "CodeQL", matches: [true, false, false, false, false, true, false, true] },
  { name: "Semgrep", matches: [false, false, false, true, false, true, false, true] },
  { name: "ASL V6", matches: [true, true, true, true, true, true, true, true], isHighlight: true },
];

export default function Benchmarks() {
  return (
    <section id="benchmarks" className="py-32 bg-black border-t border-white/5 relative">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom,rgba(147,51,234,0.05),transparent_60%)]" />
      
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center mb-24">
          <h2 className="text-4xl md:text-5xl font-bold tracking-tighter mb-4 font-display">
            The New Standard
          </h2>
          <p className="text-xl text-white/50 font-light">
            Why traditional tools fail to secure modern AI stacks.
          </p>
        </div>

        <motion.div 
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
          className="overflow-x-auto rounded-3xl border border-white/10 bg-card/50 backdrop-blur-xl shadow-2xl"
        >
          <table className="w-full text-left border-collapse">
            <thead>
              <tr>
                <th className="p-6 border-b border-white/10 text-white/50 font-medium w-1/3">Capability</th>
                {competitors.map((comp) => (
                  <th key={comp.name} className={`p-6 border-b border-white/10 font-semibold text-center ${comp.isHighlight ? 'text-primary-cyan bg-primary-DEFAULT/5' : 'text-white/80'}`}>
                    {comp.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {features.map((feature, i) => (
                <tr key={feature} className="hover:bg-white/[0.02] transition-colors">
                  <td className="p-6 border-b border-white/5 text-sm font-medium text-white/80">{feature}</td>
                  {competitors.map((comp, j) => (
                    <td key={j} className={`p-6 border-b border-white/5 text-center ${comp.isHighlight ? 'bg-primary-DEFAULT/5' : ''}`}>
                      <div className="flex justify-center">
                        {comp.matches[i] === true ? (
                          <div className={`w-6 h-6 rounded-full flex items-center justify-center ${comp.isHighlight ? 'bg-primary-cyan/20 text-primary-cyan' : 'bg-white/10 text-white/60'}`}>
                            <Check className="w-4 h-4" />
                          </div>
                        ) : comp.matches[i] === false ? (
                          <X className="w-4 h-4 text-white/20" />
                        ) : (
                          <Minus className="w-4 h-4 text-white/20" />
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>
      </div>
    </section>
  );
}
