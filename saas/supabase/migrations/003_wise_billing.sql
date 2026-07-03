-- Remove Stripe fields from users
ALTER TABLE public.users 
  DROP COLUMN IF EXISTS stripe_customer_id,
  DROP COLUMN IF EXISTS stripe_subscription_id;

-- Remove Stripe fields from organizations
ALTER TABLE public.organizations 
  DROP COLUMN IF EXISTS stripe_customer_id;

-- Update subscriptions table
ALTER TABLE public.subscriptions 
  DROP COLUMN IF EXISTS stripe_subscription_id,
  DROP COLUMN IF EXISTS stripe_customer_id,
  ADD COLUMN IF NOT EXISTS payment_reference TEXT;

-- Update invoices table
ALTER TABLE public.invoices 
  DROP COLUMN IF EXISTS stripe_invoice_id,
  DROP COLUMN IF EXISTS invoice_url,
  DROP COLUMN IF EXISTS invoice_pdf,
  ADD COLUMN IF NOT EXISTS payment_reference TEXT,
  ADD COLUMN IF NOT EXISTS payment_proof_url TEXT;
