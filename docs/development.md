# CoreFlow360 V4 - Development Guide

Complete guide for setting up and running CoreFlow360 V4 in your local development environment.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start (5 Minutes)](#quick-start-5-minutes)
- [Detailed Setup](#detailed-setup)
- [Running the Application](#running-the-application)
- [Environment Configuration](#environment-configuration)
- [Database Setup](#database-setup)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Development Workflow](#development-workflow)

---

## Prerequisites

Before you begin, ensure you have the following installed:

### Required

- **Node.js 22+** (Required - engineStrict enforced)
  ```bash
  node --version  # Must be v22.0.0 or higher
  ```

- **npm 10+** (Comes with Node.js)
  ```bash
  npm --version
  ```

- **Wrangler CLI** (Cloudflare Workers CLI)
  ```bash
  npm install -g wrangler
  wrangler --version
  ```

### Optional but Recommended

- **Git** for version control
- **VS Code** with recommended extensions:
  - ESLint
  - Prettier
  - TypeScript and JavaScript Language Features
  - Tailwind CSS IntelliSense

---

## Quick Start (5 Minutes)

Get up and running quickly with these steps:

```bash
# 1. Clone the repository
git clone https://github.com/your-org/coreflow360-v4.git
cd coreflow360-v4

# 2. Install dependencies (root + frontend)
npm install
cd frontend && npm install && cd ..

# 3. Set up environment variables
cp .env.example .env.local

# 4. Login to Cloudflare (if not already logged in)
wrangler login

# 5. Run both backend and frontend
npm run dev:full
```

The application will be available at:
- **Frontend**: http://localhost:5173
- **Backend (Worker)**: http://127.0.0.1:8787

---

## Detailed Setup

### Step 1: Install Dependencies

#### Root Dependencies
```bash
npm install
```

This installs backend dependencies including:
- Cloudflare Workers SDK
- Hono web framework
- Testing tools (Vitest)
- Audit tools (axe-core, Lighthouse)

#### Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

This installs:
- React 19
- TanStack Router
- Tailwind CSS
- UI components
- Web vitals monitoring

### Step 2: Environment Configuration

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env.local
   ```

2. **Configure required variables:**

   Edit `.env.local` and set these critical values:

   ```bash
   # Authentication (CRITICAL)
   JWT_SECRET=your_secure_random_string_minimum_32_chars

   # Anthropic Claude API (for AI features)
   ANTHROPIC_API_KEY=your_anthropic_api_key

   # Cloudflare
   CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
   ```

3. **Generate secure secrets:**
   ```bash
   # Generate JWT secret
   openssl rand -base64 32
   ```

### Step 3: Cloudflare Setup

#### Login to Cloudflare
```bash
wrangler login
```

This will open a browser window for authentication.

#### Verify Account Access
```bash
wrangler whoami
```

You should see your Cloudflare account details.

#### Set Production Secrets (Optional)
For production deployments, set secrets via Wrangler:

```bash
wrangler secret put JWT_SECRET --env production
wrangler secret put ANTHROPIC_API_KEY --env production
```

### Step 4: Database Setup

CoreFlow360 uses Cloudflare D1 (SQLite) for data storage.

#### Create Local Database
```bash
# D1 databases are created automatically in local development
# The worker will use a local SQLite database
```

#### Run Migrations (if needed)
```bash
npx wrangler d1 migrations apply coreflow360-agents --local
```

---

## Running the Application

### Development Mode

#### Option 1: Run Both Frontend and Backend Together (Recommended)
```bash
npm run dev:full
```

This starts:
- **Backend**: Wrangler dev server on http://127.0.0.1:8787
- **Frontend**: Vite dev server on http://localhost:5173

#### Option 2: Run Separately

**Backend only:**
```bash
npm run dev:watch
```

**Frontend only:**
```bash
cd frontend
npm run dev
```

### Production Build

#### Build Backend
```bash
npm run build:production
```

#### Build Frontend
```bash
cd frontend
npm run build
```

---

## Environment Configuration

### Frontend Environment Variables

Frontend variables must be prefixed with `VITE_`:

```bash
VITE_API_URL=http://127.0.0.1:8787
VITE_CLARITY_ID=disabled  # Microsoft Clarity analytics ID
```

### Backend Environment Variables

See `.env.example` for all available variables.

**Critical variables:**
- `JWT_SECRET` - Authentication secret
- `ANTHROPIC_API_KEY` - AI service key
- `AGENT_SYSTEM_ENABLED` - Enable/disable AI agents

---

## Database Setup

### Local Development

Local D1 databases are stored in `.wrangler/state/d1/`:

```bash
# View local database
npx wrangler d1 execute coreflow360-agents --local --command "SELECT * FROM users LIMIT 5"
```

### Running Migrations

```bash
# Local
npx wrangler d1 migrations apply coreflow360-agents --local

# Remote (staging/production)
npx wrangler d1 migrations apply coreflow360-agents --remote
```

### Creating New Migrations

1. Create a new file in `database/migrations/`:
   ```sql
   -- 100_your_migration_name.sql
   CREATE TABLE IF NOT EXISTS your_table (
     id TEXT PRIMARY KEY,
     created_at TEXT NOT NULL
   );
   ```

2. Run the migration:
   ```bash
   npx wrangler d1 migrations apply coreflow360-agents --local
   ```

---

## Testing

### Run All Tests
```bash
npm test
```

### Run Tests with Coverage
```bash
npm run test:coverage
```

### Run Specific Test Suites

```bash
# Security tests
npm run test:security

# Integration tests
npm run test:integration

# Performance tests
npm run test:performance
```

### Accessibility Audits
```bash
# Run axe accessibility audit
npm run audit:a11y

# Run Lighthouse performance audit
npm run audit:lighthouse

# Run worker latency audit
npm run audit:worker-latency
```

---

## Troubleshooting

### Common Issues

#### Issue: "FATAL: React.useEffect is undefined"

**Solution**: Ensure you're using Node.js 22+
```bash
node --version  # Must be 22.0.0+
```

#### Issue: "Wrangler command not found"

**Solution**: Install Wrangler globally
```bash
npm install -g wrangler
```

#### Issue: "Failed to fetch worker"

**Solution**: Ensure the backend is running
```bash
# Check if worker is running
curl http://127.0.0.1:8787/health

# Should return: {"success":true,"status":"operational"}
```

#### Issue: "Module not found" errors

**Solution**: Clear node_modules and reinstall
```bash
rm -rf node_modules frontend/node_modules
npm install
cd frontend && npm install
```

#### Issue: "Database not found"

**Solution**: Create local database
```bash
npx wrangler d1 create coreflow360-agents
npx wrangler d1 migrations apply coreflow360-agents --local
```

### Logs & Debugging

#### View Worker Logs
```bash
npx wrangler tail --env development
```

#### View Frontend Logs
Check browser console (F12 -> Console tab)

#### Enable Verbose Logging
```bash
# Add to .env.local
LOG_LEVEL=debug
VERBOSE_LOGGING=true
```

---

## Development Workflow

### Daily Development

1. **Pull latest changes:**
   ```bash
   git pull origin main
   ```

2. **Install any new dependencies:**
   ```bash
   npm install
   cd frontend && npm install
   ```

3. **Start development servers:**
   ```bash
   npm run dev:full
   ```

4. **Run tests before committing:**
   ```bash
   npm run test
   npm run type-check
   ```

### Making Changes

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**

3. **Run quality checks:**
   ```bash
   npm run quality:check  # Format, lint, type-check
   ```

4. **Run tests:**
   ```bash
   npm run test:coverage
   ```

5. **Commit and push:**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   git push origin feature/your-feature-name
   ```

### Code Quality Commands

```bash
# Format code
npm run format

# Lint and fix
npm run lint:fix

# Type check
npm run type-check

# All quality checks
npm run quality:check
```

---

## Additional Resources

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Hono Framework Docs](https://hono.dev/)
- [TanStack Router Docs](https://tanstack.com/router)
- [Vite Docs](https://vitejs.dev/)

---

## Getting Help

- **Documentation**: Check `/docs` directory
- **Issues**: https://github.com/your-org/coreflow360-v4/issues
- **Internal Slack**: #coreflow360-dev

---

## Next Steps

After setting up your development environment:

1. ✅ Complete the [Quick Start](#quick-start-5-minutes)
2. 📖 Read the [CLAUDE.md](../CLAUDE.md) for project overview
3. 🧪 Run the test suite with `npm test`
4. 🎨 Explore the frontend at http://localhost:5173
5. 🔧 Check the API at http://127.0.0.1:8787/health

Happy coding! 🚀
