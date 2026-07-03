"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, Minus } from "lucide-react";

const faqs = [
  {
    q: "How does ASL V6 differ from traditional SAST tools?",
    a: "Traditional SAST tools rely on simple regex or basic AST matching, leading to massive false positive rates when applied to AI applications. ASL V6 uses a 10-layer pipeline that includes Reachability Analysis (to see if the vulnerability is actually exploitable) and an AI-assisted Review engine (compatible with NVIDIA NIM) to intelligently validate findings.",
  },
  {
    q: "Do you support custom internal frameworks?",
    a: "Yes. Our enterprise tier allows you to write custom detection rules and context mappers to secure proprietary AI architectures and internal RAG pipelines.",
  },
  {
    q: "How long does a typical scan take?",
    a: "Thanks to our Rust-based static analysis engine and optimized AI triage layer, a complete 10-layer scan of a standard AI microservice typically completes in under 3 minutes.",
  },
  {
    q: "Can I deploy ASL V6 in my own VPC?",
    a: "Absolutely. We offer an On-Premise / VPC deployment option for Enterprise customers who require absolute data residency and cannot use our managed cloud.",
  },
];

export default function FAQ() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  return (
    <section className="py-32 bg-[#02040A] relative">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold tracking-tighter mb-4 font-display">
            Frequently Asked Questions
          </h2>
        </div>

        <div className="space-y-4">
          {faqs.map((faq, i) => (
            <div 
              key={i} 
              className={`border border-white/5 rounded-2xl overflow-hidden transition-colors ${openIndex === i ? 'bg-white/[0.03]' : 'bg-transparent hover:bg-white/[0.01]'}`}
            >
              <button
                className="w-full px-6 py-5 text-left flex justify-between items-center"
                onClick={() => setOpenIndex(openIndex === i ? null : i)}
              >
                <span className="font-semibold text-white/90">{faq.q}</span>
                {openIndex === i ? (
                  <Minus className="w-5 h-5 text-primary-cyan flex-shrink-0" />
                ) : (
                  <Plus className="w-5 h-5 text-white/40 flex-shrink-0" />
                )}
              </button>
              <AnimatePresence>
                {openIndex === i && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3, ease: "easeInOut" }}
                  >
                    <div className="px-6 pb-5 text-white/50 font-light text-sm leading-relaxed">
                      {faq.a}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
