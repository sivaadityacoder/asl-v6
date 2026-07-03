"use client";

import React from "react";
import { Lock, Users, Activity, Layout, ShieldCheck, Key } from "lucide-react";

const features = [
  { icon: Lock, title: "Military-Grade Encryption", desc: "AES-256 at rest, TLS 1.3 in transit." },
  { icon: Users, title: "Granular RBAC", desc: "Custom roles and permissions for enterprise teams." },
  { icon: Activity, title: "Immutable Audit Logs", desc: "Every action is tracked, signed, and tamper-proof." },
  { icon: Layout, title: "Strict Tenant Isolation", desc: "Data boundaries enforced at the infrastructure level." },
  { icon: ShieldCheck, title: "SOC2 & HIPAA Ready", desc: "Engineered to meet the strictest compliance standards." },
  { icon: Key, title: "API Security", desc: "Rate limiting, IP allowlisting, and automated token rotation." },
];

export default function Security() {
  return (
    <section className="py-24 bg-black relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row gap-16 items-center">
          
          <div className="w-full md:w-1/3">
            <h2 className="text-3xl md:text-5xl font-bold tracking-tighter mb-4 font-display">
              Enterprise <br/><span className="text-primary-cyan">Security</span>
            </h2>
            <p className="text-white/50 font-light mb-8">
              We secure the tools that secure your AI. ASL V6 is built from the ground up with a zero-trust architecture.
            </p>
          </div>

          <div className="w-full md:w-2/3 grid sm:grid-cols-2 gap-6">
            {features.map((feat, i) => (
              <div key={i} className="flex gap-4 p-6 rounded-2xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-colors">
                <div className="mt-1">
                  <feat.icon className="w-5 h-5 text-primary-cyan" />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-white/90 mb-1">{feat.title}</h4>
                  <p className="text-xs text-white/40 leading-relaxed">{feat.desc}</p>
                </div>
              </div>
            ))}
          </div>

        </div>
      </div>
    </section>
  );
}
