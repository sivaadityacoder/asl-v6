import type { Metadata } from 'next';
import { Inter, Space_Grotesk } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';

const inter = Inter({ 
  subsets: ['latin'],
  variable: '--font-inter',
});

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-space-grotesk',
});

export const metadata: Metadata = {
  title: 'ASL V6 | AI Security Platform',
  description: 'Automated security scanning for AI/LLM applications. Detect vulnerabilities across OWASP Top 10 LLM, MITRE ATLAS, and more.',
  keywords: ['AI security', 'LLM security', 'vulnerability scanning', 'OWASP LLM', 'MITRE ATLAS', 'bug bounty'],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} ${spaceGrotesk.variable} antialiased dark bg-background text-foreground`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}