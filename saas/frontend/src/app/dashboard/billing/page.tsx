"use client";

import { useState, useEffect } from "react";
import { CreditCard, CheckCircle2, AlertCircle, Building, Users, Zap, Shield, ArrowRight, X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSession } from "next-auth/react";

interface BankDetails {
  account_name: string;
  iban: string;
  swift_bic: string;
  routing_number?: string;
  account_number?: string;
}

interface Subscription {
  plan_tier: string;
  status: string;
}

const PLANS = [
  {
    name: "Starter",
    tier: "starter",
    price: "$0",
    description: "For individuals and small open-source projects.",
    features: ["Up to 3 projects", "Basic AI scans", "Community support", "Shared infrastructure"],
    icon: Shield
  },
  {
    name: "Pro",
    tier: "pro",
    price: "$49",
    period: "/mo",
    description: "For professional developers and small teams.",
    features: ["Unlimited projects", "Advanced AI models", "Priority scanning queue", "Email support", "API access"],
    icon: Zap
  },
  {
    name: "Team",
    tier: "team",
    price: "$149",
    period: "/mo",
    description: "For growing security teams.",
    features: ["Everything in Pro", "Up to 10 team members", "Custom rule creation", "SSO integration", "Dedicated support"],
    icon: Users
  },
  {
    name: "Enterprise",
    tier: "enterprise",
    price: "$499",
    period: "/mo",
    description: "For large organizations with strict compliance needs.",
    features: ["Everything in Team", "Unlimited members", "Self-hosted agents", "Custom AI fine-tuning", "SLA guarantees"],
    icon: Building
  }
];

export default function BillingPage() {
  const { data: session } = useSession();
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [bankDetails, setBankDetails] = useState<BankDetails | null>(null);
  const [loading, setLoading] = useState(true);
  
  // Checkout State
  const [selectedTier, setSelectedTier] = useState<string | null>(null);
  const [isCheckoutOpen, setIsCheckoutOpen] = useState(false);
  const [invoiceId, setInvoiceId] = useState<string | null>(null);
  const [transactionRef, setTransactionRef] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [checkoutStep, setCheckoutStep] = useState<"details" | "verify">("details");
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  useEffect(() => {
    async function fetchData() {
      // @ts-ignore - session.organization exists in our auth context
      if (!session?.organization?.id) {
        setLoading(false);
        return;
      }
      
      try {
        const [subRes, bankRes] = await Promise.all([
          // @ts-ignore
          fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/v1/billing/subscription?organization_id=${session.organization.id}`, {
            // @ts-ignore
            headers: { Authorization: `Bearer ${session.access_token}` }
          }),
          // @ts-ignore
          fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/v1/billing/bank-details`, {
            // @ts-ignore
            headers: { Authorization: `Bearer ${session.access_token}` }
          })
        ]);
        
        if (subRes.ok) {
          const subData = await subRes.json();
          setSubscription(subData);
        }
        
        if (bankRes.ok) {
          const bankData = await bankRes.json();
          setBankDetails(bankData);
        }
      } catch (error) {
        console.error("Error fetching billing data:", error);
      } finally {
        setLoading(false);
      }
    }
    
    fetchData();
  }, [session]);

  const handleUpgradeClick = async (tier: string) => {
    setSelectedTier(tier);
    setIsCheckoutOpen(true);
    setCheckoutStep("details");
    setErrorMsg("");
    setSuccessMsg("");
    
    try {
      // @ts-ignore
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/v1/billing/checkout?organization_id=${session?.organization?.id}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // @ts-ignore
          Authorization: `Bearer ${session?.access_token}`
        },
        body: JSON.stringify({ plan_tier: tier })
      });
      
      if (res.ok) {
        const data = await res.json();
        setInvoiceId(data.invoice_id);
      } else {
        setErrorMsg("Failed to initiate checkout");
      }
    } catch (error) {
      console.error(error);
      setErrorMsg("Network error occurred");
    }
  };

  const handleVerifySubmit = async () => {
    if (!transactionRef.trim() || !invoiceId) {
      setErrorMsg("Please enter your transaction reference number");
      return;
    }
    
    setIsSubmitting(true);
    setErrorMsg("");
    
    try {
      // @ts-ignore
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/v1/billing/verify?organization_id=${session?.organization?.id}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // @ts-ignore
          Authorization: `Bearer ${session?.access_token}`
        },
        body: JSON.stringify({
          invoice_id: invoiceId,
          payment_reference: transactionRef
        })
      });
      
      if (res.ok) {
        setSuccessMsg("Payment reference submitted for verification!");
        setTimeout(() => {
          setIsCheckoutOpen(false);
          // Optimistic UI update
          setSubscription(prev => prev ? { ...prev, plan_tier: selectedTier!, status: "pending_verification" } : { plan_tier: selectedTier!, status: "pending_verification" });
        }, 1500);
      } else {
        setErrorMsg("Failed to submit verification");
      }
    } catch (error) {
      setErrorMsg("Network error occurred");
    } finally {
      setIsSubmitting(false);
    }
  };

  if (loading) {
    return <div className="animate-pulse space-y-6">
      <div className="h-8 bg-muted rounded w-1/4"></div>
      <div className="h-64 bg-muted rounded w-full"></div>
    </div>;
  }

  const currentTier = subscription?.status === "active" ? subscription.plan_tier : "starter";
  const isPending = subscription?.status === "pending_verification";

  return (
    <div className="space-y-8 pb-10">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Billing & Plans</h1>
        <p className="text-muted-foreground mt-1">Manage your organization's subscription</p>
      </div>
      
      {isPending && (
        <div className="flex p-4 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 dark:bg-amber-950/50 dark:border-amber-900 dark:text-amber-200">
          <AlertCircle className="h-5 w-5 mr-3 mt-0.5 shrink-0" />
          <div>
            <h5 className="font-medium mb-1">Verification Pending</h5>
            <p className="text-sm">
              Your upgrade to the <strong>{subscription.plan_tier.toUpperCase()}</strong> plan is currently pending verification. An administrator will review your payment reference shortly.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {PLANS.map((plan) => {
          const Icon = plan.icon;
          const isActive = currentTier === plan.tier;
          const isPendingThisPlan = isPending && subscription?.plan_tier === plan.tier;
          
          return (
            <Card key={plan.tier} className={`flex flex-col ${isActive ? 'border-primary shadow-md relative' : ''}`}>
              {isActive && (
                <div className="absolute top-0 right-0 transform translate-x-2 -translate-y-2">
                  <span className="bg-primary text-primary-foreground text-xs font-bold px-3 py-1 rounded-full shadow">
                    Current Plan
                  </span>
                </div>
              )}
              <CardHeader>
                <div className="flex items-center gap-2 mb-2">
                  <div className={`p-2 rounded-lg ${isActive ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <CardTitle>{plan.name}</CardTitle>
                </div>
                <div className="flex items-baseline gap-1 mt-2">
                  <span className="text-3xl font-bold">{plan.price}</span>
                  {plan.period && <span className="text-muted-foreground">{plan.period}</span>}
                </div>
                <CardDescription className="pt-2">{plan.description}</CardDescription>
              </CardHeader>
              <CardContent className="flex-1">
                <ul className="space-y-2 text-sm">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                      <span className="text-muted-foreground">{feature}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
              <CardFooter>
                {isActive ? (
                  <Button variant="outline" className="w-full" disabled>Active</Button>
                ) : isPendingThisPlan ? (
                  <Button variant="secondary" className="w-full" disabled>Pending Review...</Button>
                ) : (
                  <Button 
                    variant={plan.tier === 'starter' ? 'outline' : 'default'} 
                    className="w-full"
                    onClick={() => handleUpgradeClick(plan.tier)}
                    disabled={isPending || plan.tier === 'starter'}
                  >
                    Upgrade
                  </Button>
                )}
              </CardFooter>
            </Card>
          );
        })}
      </div>

      {isCheckoutOpen && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-card text-card-foreground border rounded-xl shadow-lg w-full max-w-md overflow-hidden relative">
            <Button 
              variant="ghost" 
              size="icon" 
              className="absolute top-2 right-2 rounded-full"
              onClick={() => setIsCheckoutOpen(false)}
            >
              <X className="w-4 h-4" />
            </Button>
            
            <div className="p-6">
              <h2 className="text-xl font-semibold leading-none tracking-tight mb-2">
                Upgrade to {selectedTier?.toUpperCase()}
              </h2>
              <p className="text-sm text-muted-foreground mb-6">
                We process payments securely via Wise Business bank transfers.
              </p>
              
              {errorMsg && (
                <div className="mb-4 p-3 bg-destructive/10 text-destructive text-sm rounded-md border border-destructive/20">
                  {errorMsg}
                </div>
              )}
              
              {successMsg && (
                <div className="mb-4 p-3 bg-green-50 text-green-700 text-sm rounded-md border border-green-200">
                  {successMsg}
                </div>
              )}
              
              {checkoutStep === "details" && bankDetails && (
                <div className="space-y-4">
                  <div className="bg-muted p-4 rounded-lg space-y-3">
                    <p className="text-sm font-medium mb-2 text-primary">Transfer Details</p>
                    <div className="grid grid-cols-3 gap-2 text-sm">
                      <div className="text-muted-foreground">Account Name:</div>
                      <div className="col-span-2 font-mono break-all">{bankDetails.account_name}</div>
                      
                      <div className="text-muted-foreground">IBAN:</div>
                      <div className="col-span-2 font-mono break-all">{bankDetails.iban}</div>
                      
                      <div className="text-muted-foreground">SWIFT/BIC:</div>
                      <div className="col-span-2 font-mono break-all">{bankDetails.swift_bic}</div>
                      
                      {bankDetails.routing_number && (
                        <>
                          <div className="text-muted-foreground">Routing:</div>
                          <div className="col-span-2 font-mono break-all">{bankDetails.routing_number}</div>
                        </>
                      )}
                    </div>
                  </div>
                  <p className="text-sm text-muted-foreground text-center">
                    Please transfer the exact amount and then proceed to verify your payment.
                  </p>
                  <Button className="w-full" onClick={() => { setCheckoutStep("verify"); setErrorMsg(""); }}>
                    I have made the transfer <ArrowRight className="ml-2 w-4 h-4" />
                  </Button>
                </div>
              )}

              {checkoutStep === "verify" && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="reference">Transaction Reference Number</Label>
                    <Input 
                      id="reference" 
                      placeholder="e.g. TR-987654321" 
                      value={transactionRef}
                      onChange={(e) => setTransactionRef(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      You can find this on your bank statement or Wise transfer receipt.
                    </p>
                  </div>
                  <div className="flex gap-2 justify-end mt-6">
                    <Button variant="outline" onClick={() => setCheckoutStep("details")} disabled={isSubmitting}>Back</Button>
                    <Button onClick={handleVerifySubmit} disabled={isSubmitting || !transactionRef}>
                      {isSubmitting ? "Submitting..." : "Submit Verification"}
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
