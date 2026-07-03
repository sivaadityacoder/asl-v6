import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default async function FindingDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Finding Details</h1>
        <p className="text-muted-foreground mt-1">View finding details and remediation steps</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Finding: {id}</CardTitle>
          <CardDescription>Detailed view for a security finding</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-center h-48 rounded-lg border border-dashed border-border bg-muted/30">
            <p className="text-sm text-muted-foreground">Content for finding {id}</p>
          </div>
          <Button asChild variant="outline">
            <Link href="/dashboard/findings">Back to Findings</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
