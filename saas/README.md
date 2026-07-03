# ASL V6 - AI Security Platform (Public SaaS)

## Overview

ASL V6 is a comprehensive AI/LLM security platform that automatically scans AI applications for vulnerabilities across OWASP Top 10 LLM 2025, OWASP Top 10 for Agents 2026, and MITRE ATLAS frameworks.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Vercel    │────▶│   Fly.io    │────▶│  Supabase   │
│  (Frontend) │     │  (Backend)  │     │  (Database) │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                    │
                    ┌──────┴──────┐       ┌──────┴──────┐
                    │    Redis    │       │  Storage    │
                    │  (Upstash)  │       │  (Buckets)  │
                    └─────────────┘       └─────────────┘
                           │
                    ┌──────┴──────┐
                    │   NVIDIA    │
                    │    API      │
                    └─────────────┘
```

## Tech Stack

### Frontend
- **Next.js 15** with App Router
- **React 19** with TypeScript
- **Tailwind CSS** + **shadcn/ui**
- **TanStack Query** for data fetching
- **Zustand** for state management
- **Monaco Editor** for code viewing

### Backend
- **FastAPI** with Python 3.11
- **Supabase** (PostgreSQL + Auth + Storage)
- **Redis** (Upstash) for caching & Celery
- **Celery** for background task processing
- **NVIDIA API** for AI-powered triage

### Infrastructure
- **Vercel** for frontend hosting
- **Fly.io** for backend hosting
- **GitHub Actions** for CI/CD
- **Docker** for containerization

## 10-Layer Scan Pipeline

1. **Repository Discovery** - Clone & profile AI stack (frameworks, components, secrets)
2. **Static Analysis** - AST parsing + Semgrep + Bandit
3. **Secrets Scanning** - Gitleaks + custom patterns
4. **Reachability Analysis** - Attack path tracing via data flow
5. **Context Analysis** - 10 specialist AI agents (prompt injection, RAG, MCP, agents, etc.)
6. **OWASP LLM Top 10** - LLM01-LLM10 vulnerability coverage
7. **MITRE ATLAS** - 16 tactics, 84+ techniques mapping
8. **Dynamic Validation** - DAST for AI endpoints
9. **AI Review** - NVIDIA-powered finding triage & prioritization
10. **Evidence Collection** - Reproducible PoCs & remediation

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 22+
- Docker & Docker Compose
- Supabase account
- NVIDIA API key
- GitHub OAuth app

### Local Development

1. **Clone and setup**
```bash
cd v6/saas
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env.local
```

2. **Configure environment variables** (see `.env.example` files)

3. **Start with Docker Compose**
```bash
cd infrastructure/docker
docker-compose up -d
```

4. **Access services**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Flower (Celery): http://localhost:5555

### Database Setup

Run the Supabase schema:
```bash
# In Supabase SQL Editor, run:
# infrastructure/supabase/schema.sql
# infrastructure/supabase/storage_policies.sql
```

## Deployment

### Backend (Fly.io)
```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login and deploy
flyctl auth login
flyctl launch --config infrastructure/fly/fly.toml
flyctl secrets set SUPABASE_URL=... SUPABASE_ANON_KEY=... # etc
flyctl deploy
```

### Frontend (Vercel)
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
cd frontend
vercel --prod
```

### Environment Variables (Production)

**Backend (Fly.io secrets):**
```bash
flyctl secrets set \
  SUPABASE_URL=... \
  SUPABASE_ANON_KEY=... \
  SUPABASE_SERVICE_ROLE_KEY=... \
  SUPABASE_JWT_SECRET=... \
  REDIS_URL=... \
  GITHUB_CLIENT_ID=... \
  GITHUB_CLIENT_SECRET=... \
  GITHUB_WEBHOOK_SECRET=... \
  NVIDIA_API_KEY=... \
  CELERY_BROKER_URL=... \
  CELERY_RESULT_BACKEND=... \
  SECRET_KEY=... \
  STRIPE_SECRET_KEY=... \
  STRIPE_WEBHOOK_SECRET=...
```

**Frontend (Vercel):**
```
NEXT_PUBLIC_API_URL=https://api.aslv6.com
NEXT_PUBLIC_SUPABASE_URL=...
NEXT_PUBLIC_SUPABASE_ANON_KEY=...
```

## Project Structure

```
v6/saas/
├── backend/                    # FastAPI Backend
│   ├── app/
│   │   ├── api/v1/endpoints/  # API endpoints
│   │   ├── core/              # Config, database, redis
│   │   ├── models/            # Pydantic models
│   │   ├── services/          # Scan worker, report generator
│   │   └── main.py            # FastAPI app
│   ├── pyproject.toml
│   └── .env.example
├── frontend/                   # Next.js Frontend
│   ├── src/
│   │   ├── app/               # App router pages
│   │   ├── components/        # React components
│   │   └── lib/               # Utilities
│   ├── package.json
│   └── .env.example
├── infrastructure/
│   ├── docker/                # Dockerfiles & compose
│   ├── fly/                   # Fly.io config
│   ├── vercel/                # Vercel config
│   └── supabase/              # Database schema
└── .github/workflows/         # CI/CD pipelines
```

## API Documentation

- **Base URL**: `https://api.aslv6.com/api/v1`
- **Interactive Docs**: `https://api.aslv6.com/docs`
- **Authentication**: Bearer token (Supabase JWT)

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Email/password login |
| POST | `/auth/github` | GitHub OAuth |
| GET | `/organizations` | List user's organizations |
| POST | `/projects` | Create project |
| POST | `/repositories/connect` | Connect GitHub repo |
| POST | `/scans` | Start new scan |
| GET | `/scans/{id}/live` | Live scan progress |
| GET | `/findings` | List findings with filters |
| PUT | `/findings/{id}` | Update finding status |
| POST | `/reports` | Generate report |
| GET | `/reports/{id}/download` | Download report |
| POST | `/ai/analyze` | Analyze code with NVIDIA AI |
| POST | `/ai/review-findings` | AI-powered triage |
| POST | `/github/webhook` | GitHub webhook handler |

## Security Features

- **Row Level Security** (RLS) on all Supabase tables
- **JWT-based authentication** with refresh tokens
- **GitHub OAuth** with PKCE
- **Rate limiting** on API endpoints
- **CORS** configured for production domains
- **Security headers** (HSTS, CSP, etc.)
- **Audit logging** for all sensitive operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest` (backend) / `npm test` (frontend)
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: https://docs.aslv6.com
- Issues: https://github.com/asl-security/asl-v6/issues
- Email: support@aslv6.com