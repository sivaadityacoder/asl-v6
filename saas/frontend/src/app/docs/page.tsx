import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { FileText, Terminal, Code2, Shield, ArrowRight } from 'lucide-react';
import Navbar from '@/components/landing/Navbar';

const docs = [
  { icon: Terminal, title: 'CLI Reference', desc: 'Scan locally with the ASL V6 CLI tool' },
  { icon: Code2, title: 'API Reference', desc: 'Full REST API documentation for integrations' },
  { icon: Shield, title: 'Security Rules', desc: 'OWASP LLM Top 10 & MITRE ATLAS rule descriptions' },
  { icon: FileText, title: 'Report Formats', desc: 'SARIF, PDF, and custom report templates' },
];

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
        <div className="text-center mb-20">
          <h1 className="text-5xl font-bold tracking-tighter mb-6 font-display">Documentation</h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Everything you need to integrate and master ASL V6.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {docs.map((doc, i) => (
            <Card key={i} className="hover:border-primary/30 transition-colors cursor-pointer">
              <CardHeader>
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center mb-3">
                  <doc.icon className="h-5 w-5 text-primary" />
                </div>
                <CardTitle className="text-lg">{doc.title}</CardTitle>
                <CardDescription>{doc.desc}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center text-sm text-primary hover:underline">
                  Read more <ArrowRight className="ml-2 h-3 w-3" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </main>
    </div>
  );
}
