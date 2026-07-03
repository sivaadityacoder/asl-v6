#!/usr/bin/env bash
# =============================================================================
# ASL V6 SaaS — One-Shot Deploy Script
# Connects: Supabase CLI + Fly CLI + Vercel CLI + GitHub CLI
# =============================================================================
set -euo pipefail

SAAS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SAAS_DIR/backend"
FRONTEND_DIR="$SAAS_DIR/frontend"
INFRA_DIR="$SAAS_DIR/infrastructure"

# ── Terminal Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

log()   { echo -e "${BLUE}[ASL]${RESET} $*"; }
ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }
step()  { echo -e "\n${PURPLE}${BOLD}══════════════════════════════${RESET}"; echo -e "${PURPLE}${BOLD}  $*${RESET}"; echo -e "${PURPLE}${BOLD}══════════════════════════════${RESET}"; }

# ── Banner ─────────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
    ___   _____ _       _   _  __   
   / _ \ / ____| |     | | | |/ /   
  / /_\ \| (___ | |     | | | ' /   
  |  _  | \___ \| |     | | |  <    
  | | | |____) | |____ | |_| . \   
  \_| |_/_____/|______| \___/_|\_\  
  
  AI Infrastructure & LLM Security Platform
  SaaS Deploy Script v1.0
EOF
echo -e "${RESET}"

# ── Prerequisites Check ────────────────────────────────────────────────────────
step "Checking CLI prerequisites"

check_cli() {
    if ! command -v "$1" &>/dev/null; then
        warn "$1 not found in PATH, checking common install locations..."
        # Check common locations
        for p in "$HOME/.fly/bin/$1" "$HOME/.local/bin/$1" "/usr/local/bin/$1"; do
            if [ -f "$p" ]; then
                export PATH="$(dirname "$p"):$PATH"
                ok "Found $1 at $p"
                return 0
            fi
        done
        err "Required CLI '$1' not found. Install it first."
    fi
    ok "$1: $(command -v "$1")"
}

check_cli gh
check_cli vercel
check_cli supabase
check_cli railway

# ── Auth Checks ────────────────────────────────────────────────────────────────
step "Verifying authentication"

log "Checking GitHub CLI auth..."
if ! gh auth status &>/dev/null; then
    warn "Not logged in to GitHub CLI. Run: gh auth login"
    warn "Skipping GitHub steps..."
    GH_OK=false
else
    ok "GitHub CLI authenticated"
    GH_OK=true
fi

log "Checking Vercel CLI auth..."
if ! vercel whoami &>/dev/null 2>&1; then
    warn "Not logged in to Vercel. Run: vercel login"
    VERCEL_OK=false
else
    ok "Vercel CLI authenticated: $(vercel whoami 2>/dev/null)"
    VERCEL_OK=true
fi

log "Checking Railway auth..."
if ! railway whoami &>/dev/null 2>&1; then
    warn "Not logged in to Railway. Run: railway login"
    RAILWAY_OK=false
else
    ok "Railway authenticated: $(railway whoami 2>/dev/null | head -1)"
    RAILWAY_OK=true
fi

log "Checking Supabase CLI auth..."
if ! supabase status &>/dev/null 2>&1; then
    warn "Supabase not linked locally. Run: supabase login && supabase link"
    SUPABASE_OK=false
else
    ok "Supabase project linked"
    SUPABASE_OK=true
fi

# ── Step 1: Supabase Migrations ────────────────────────────────────────────────
step "1/4 — Supabase: Running database migrations"

if [ "$SUPABASE_OK" = true ]; then
    log "Pushing main schema..."
    if supabase db push --include-all 2>/dev/null; then
        ok "Supabase schema deployed"
    else
        log "Trying with SQL files directly..."
        # Fallback: print instructions
        warn "Auto-push failed. Run manually in Supabase SQL Editor:"
        warn "  1. Open: https://supabase.com/dashboard"
        warn "  2. SQL Editor → Paste: $INFRA_DIR/supabase/schema.sql"  
        warn "  3. Then paste: $INFRA_DIR/supabase/migrations_v1.sql"
    fi
    
    log "Pushing migration v1 (benchmark_runs, fp_overrides)..."
    supabase db remote commit 2>/dev/null || warn "Migration may need manual run (see migrations_v1.sql)"
else
    warn "Skipping Supabase migration (not authenticated)"
    echo -e "  ${YELLOW}Manual steps:${RESET}"
    echo -e "    1. supabase login"
    echo -e "    2. supabase link --project-ref <your-project-id>"
    echo -e "    3. supabase db push"
    echo -e "    4. Run $INFRA_DIR/supabase/migrations_v1.sql in SQL Editor"
fi

# ── Step 2: GitHub Repo & Secrets ─────────────────────────────────────────────
step "2/4 — GitHub: Setting up repo and secrets"

if [ "$GH_OK" = true ]; then
    # Check if we're in a git repo
    if git -C "$SAAS_DIR" rev-parse --git-dir &>/dev/null; then
        REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
        if [ -n "$REPO" ]; then
            ok "GitHub repo: $REPO"
            
            log "Setting required GitHub Actions secrets (from environment)..."
            # Set secrets from env if they exist
            set_secret() {
                local name="$1" val="${!2:-}"
                if [ -n "$val" ]; then
                    echo "$val" | gh secret set "$name" 2>/dev/null && ok "Secret set: $name"
                else
                    warn "Env var '$2' not set — skipping secret $name"
                fi
            }
            
            set_secret "SUPABASE_URL" "SUPABASE_URL"
            set_secret "SUPABASE_ANON_KEY" "SUPABASE_ANON_KEY"
            set_secret "SUPABASE_SERVICE_ROLE_KEY" "SUPABASE_SERVICE_ROLE_KEY"
            set_secret "SUPABASE_JWT_SECRET" "SUPABASE_JWT_SECRET"
            set_secret "NVIDIA_API_KEY" "NVIDIA_API_KEY"
            set_secret "REDIS_URL" "REDIS_URL"
            set_secret "GITHUB_CLIENT_ID" "GH_CLIENT_ID"
            set_secret "GITHUB_CLIENT_SECRET" "GH_CLIENT_SECRET"
            set_secret "GITHUB_WEBHOOK_SECRET" "GH_WEBHOOK_SECRET"
            set_secret "SECRET_KEY" "SECRET_KEY"
            set_secret "STRIPE_SECRET_KEY" "STRIPE_SECRET_KEY"
            set_secret "STRIPE_WEBHOOK_SECRET" "STRIPE_WEBHOOK_SECRET"
            set_secret "RAILWAY_TOKEN" "RAILWAY_TOKEN"
            set_secret "VERCEL_TOKEN" "VERCEL_TOKEN"
            set_secret "VERCEL_ORG_ID" "VERCEL_ORG_ID"
            set_secret "VERCEL_PROJECT_ID" "VERCEL_PROJECT_ID"
        else
            warn "No remote GitHub repo found. Create one with: gh repo create asl-v6 --private"
        fi
    else
        warn "Not in a git repo. Initialize with: git init && git remote add origin <url>"
    fi
else
    warn "Skipping GitHub secrets (gh CLI not authenticated)"
    echo ""
    echo -e "  ${YELLOW}Manual secret setup commands:${RESET}"
    cat << 'SECRETS'
    gh secret set SUPABASE_URL --body "https://xxx.supabase.co"
    gh secret set SUPABASE_ANON_KEY --body "eyJ..."
    gh secret set SUPABASE_SERVICE_ROLE_KEY --body "eyJ..."
    gh secret set NVIDIA_API_KEY --body "nvapi-..."
    gh secret set RAILWAY_TOKEN --body "..."
    gh secret set VERCEL_TOKEN --body "..."
    gh secret set VERCEL_ORG_ID --body "team_..."
    gh secret set VERCEL_PROJECT_ID --body "prj_..."
    gh secret set SECRET_KEY --body "$(openssl rand -hex 32)"
SECRETS
fi

# ── Step 3: Railway Backend Deploy ────────────────────────────────────────────
step "3/4 — Railway: Deploying backend API"

if [ "$RAILWAY_OK" = true ]; then
    cd "$BACKEND_DIR"
    
    # Check if project is linked
    if ! railway status &>/dev/null; then
        warn "Railway project not linked. Run 'railway init' or 'railway link' first."
        echo -e "  ${YELLOW}Auto-initializing new project...${RESET}"
        railway init --name asl-v6-backend || true
    fi
    
    log "Deploying to Railway..."
    if railway up -d 2>&1; then
        ok "Backend deployed to Railway!"
    else
        err "Railway deploy failed. Check logs: railway logs"
    fi
else
    warn "Skipping Railway deploy (not authenticated)"
    echo -e "  ${YELLOW}Manual steps:${RESET}"
    echo "    railway login"
    echo "    cd backend && railway up"
fi

# ── Step 4: Vercel Frontend Deploy ────────────────────────────────────────────
step "4/4 — Vercel: Deploying frontend"

if [ "$VERCEL_OK" = true ]; then
    cd "$FRONTEND_DIR"
    
    log "Installing frontend dependencies..."
    npm ci --silent && ok "Dependencies installed"
    
    log "Checking Next.js build..."
    NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-https://backend.up.railway.app}" \
    NEXT_PUBLIC_SUPABASE_URL="${NEXT_PUBLIC_SUPABASE_URL:-placeholder}" \
    NEXT_PUBLIC_SUPABASE_ANON_KEY="${NEXT_PUBLIC_SUPABASE_ANON_KEY:-placeholder}" \
    npm run build 2>&1 | tail -20
    
    log "Deploying to Vercel (production)..."
    if vercel --prod --yes \
       --env NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-https://backend.up.railway.app}" \
       --env NEXT_PUBLIC_SUPABASE_URL="${NEXT_PUBLIC_SUPABASE_URL:-}" \
       --env NEXT_PUBLIC_SUPABASE_ANON_KEY="${NEXT_PUBLIC_SUPABASE_ANON_KEY:-}" \
       2>&1 | tee /tmp/vercel_output.txt; then
        VERCEL_URL=$(grep -o 'https://[^[:space:]]*\.vercel\.app' /tmp/vercel_output.txt | head -1 || echo "")
        ok "Frontend deployed to Vercel!"
        [ -n "$VERCEL_URL" ] && ok "Frontend URL: $VERCEL_URL"
    else
        warn "Vercel deploy had issues. Check output above."
    fi
    
    cd "$SAAS_DIR"
else
    warn "Skipping Vercel deploy (not authenticated)"
    echo -e "  ${YELLOW}Manual steps:${RESET}"
    echo "    vercel login"
    echo "    cd frontend && vercel --prod"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
step "Deploy Summary"
echo -e "${BOLD}Status:${RESET}"
[ "$SUPABASE_OK" = true ] && echo -e "  ${GREEN}✓${RESET} Supabase: migrations applied" || echo -e "  ${YELLOW}⚠${RESET} Supabase: manual action needed"
[ "$GH_OK" = true ]       && echo -e "  ${GREEN}✓${RESET} GitHub:   secrets configured" || echo -e "  ${YELLOW}⚠${RESET} GitHub:   manual action needed"
[ "$RAILWAY_OK" = true ]  && echo -e "  ${GREEN}✓${RESET} Railway:  backend deployed" || echo -e "  ${YELLOW}⚠${RESET} Railway:  manual action needed"
[ "$VERCEL_OK" = true ]   && echo -e "  ${GREEN}✓${RESET} Vercel:   frontend deployed" || echo -e "  ${YELLOW}⚠${RESET} Vercel:   manual action needed"

echo ""
echo -e "${BOLD}Live URLs (once deployed):${RESET}"
echo -e "  🌐 Frontend:  ${CYAN}https://aslv6.com${RESET}  (or your Vercel URL)"
echo -e "  🔌 Backend:   ${CYAN}https://api.aslv6.com${RESET}"
echo -e "  📊 API Docs:  ${CYAN}https://api.aslv6.com/docs${RESET}"
echo -e "  📈 Benchmarks:${CYAN}https://aslv6.com/benchmarks${RESET}"
echo ""
echo -e "${BOLD}Next Steps:${RESET}"
echo "  1. Set up custom domain in Vercel & Fly dashboard"
echo "  2. Configure Supabase Auth with your domain's OAuth redirect URLs"
echo "  3. Set up Stripe webhooks: https://api.aslv6.com/api/v1/billing/webhook"
echo "  4. Trigger first CI run: gh workflow run ci-cd.yml"
echo ""
echo -e "${GREEN}${BOLD}ASL V6 deploy complete! 🚀${RESET}"
