import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Navbar from '@/components/landing/Navbar';
import { Shield, Lock, Eye, Database } from 'lucide-react';

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
        <h1 className="text-4xl font-bold tracking-tighter mb-8 font-display">Privacy Policy</h1>

        <div className="space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Data Collection
              </CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground space-y-2">
              <p>ASL V6 collects only the minimum data needed to provide security scanning services:</p>
              <ul className="list-disc list-inside space-y-1 ml-4">
                <li>Email and name for account identification</li>
                <li>GitHub username (when GitHub integration is used)</li>
                <li>Repository contents temporarily during scans (not persisted)</li>
                <li>Scan results and findings metadata</li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5 text-primary" />
                Data Security
              </CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground space-y-2">
              <p>All data is encrypted in transit (TLS 1.3) and at rest. Authentication uses JWT tokens with short-lived access tokens and refresh token rotation.</p>
              <p>Secrets are managed via environment variables and never exposed to the client.</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5 text-primary" />
                Data Usage
              </CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">
              <p>We do not sell or share your data with third parties. Your code is scanned in isolated ephemeral environments and discarded after scan completion.</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5 text-primary" />
                Data Retention
              </CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">
              <p>Scan results are retained for 90 days. Account data is retained until account deletion. Account deletion is a soft-delete (deactivation) that removes access.</p>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
