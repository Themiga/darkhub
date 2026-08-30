# DarkHub — Deployment Guide

> **Restricted system.** Deploy carefully — follow every step to keep secrets secure.

---

## Project Structure

```
darkhub/
├── worker/
│   ├── wrangler.toml       ← Cloudflare Worker config (no secrets here)
│   └── src/
│       ├── index.js        ← Main router
│       ├── auth.js         ← GitHub OAuth + JWT
│       ├── scripts.js      ← Script CRUD (AES-GCM encrypted at rest)
│       ├── loader.js       ← Secure script delivery to Luau Hub
│       ├── analytics.js    ← Server-side execution tracking
│       └── security.js     ← Rate limiting, HMAC, XOR, JWT utilities
├── frontend/
│   ├── index.html          ← Public landing page
│   ├── callback.html       ← OAuth callback handler
│   ├── admin/
│   │   └── index.html      ← Admin SPA
│   └── assets/
│       ├── style.css
│       └── admin.js
└── lua/
    └── hub.lua             ← Luau Hub Loader (deploy to raw HTTP host)
```

---

## Step 1 — Prerequisites

- [Cloudflare account](https://dash.cloudflare.com) (free tier is sufficient)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/): `npm install -g wrangler`
- [GitHub account](https://github.com) (for OAuth App + Pages)
- Node.js ≥ 18

---

## Step 2 — Create the GitHub OAuth App

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
2. Fill in:
   - **Application name**: `DarkHub`
   - **Homepage URL**: `https://YOUR-USERNAME.github.io/darkhub`
   - **Authorization callback URL**: `https://YOUR-USERNAME.github.io/darkhub/callback.html`
3. Click **Register application**
4. Note your **Client ID** and generate a **Client Secret** — keep them safe

---

## Step 3 — Create Cloudflare KV Namespaces

Run each command and copy the returned `id` into `wrangler.toml`:

```bash
wrangler kv namespace create SCRIPTS_KV
wrangler kv namespace create SESSIONS_KV
wrangler kv namespace create RATELIMIT_KV
wrangler kv namespace create ANALYTICS_KV
wrangler kv namespace create NONCES_KV

# Also create preview namespaces for local dev:
wrangler kv namespace create SCRIPTS_KV   --preview
wrangler kv namespace create SESSIONS_KV  --preview
wrangler kv namespace create RATELIMIT_KV --preview
wrangler kv namespace create ANALYTICS_KV --preview
wrangler kv namespace create NONCES_KV    --preview
```

Update `worker/wrangler.toml` with the returned IDs.

---

## Step 4 — Set Cloudflare Secrets

**Never put secrets in wrangler.toml or any committed file.**

```bash
cd worker

# GitHub OAuth credentials
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET

# Your GitHub username (admin whitelist — EXACT match)
wrangler secret put ADMIN_GITHUB_LOGIN

# JWT signing secret — generate with: openssl rand -hex 32
wrangler secret put JWT_SECRET

# Shared HMAC secret for the Luau Hub — generate with: openssl rand -hex 32
# ⚠ Must match the assembled _HMAC_SECRET in hub.lua
wrangler secret put HUB_HMAC_SECRET

# AES-256-GCM key for at-rest storage — generate with: openssl rand -base64 32
wrangler secret put AES_ENCRYPTION_KEY
```

---

## Step 5 — Configure hub.lua

Open `lua/hub.lua` and update these sections:

```lua
-- § 3 CONFIGURATION

-- Worker URL (no trailing slash)
local _w1 = "https://darkhub-api"
local _w2 = ".YOUR-SUBDOMAIN"       -- ← change this
local _w3 = ".workers.dev"
local _WORKER_URL = _w1 .. _w2 .. _w3

-- HMAC secret must match HUB_HMAC_SECRET set in Cloudflare Secrets
-- Split your secret into 4 parts and encode as string.char() sequences
-- Use an online ASCII-to-decimal converter and replace _s1.._s4
local _s1 = string.char(...)  -- part 1
local _s2 = string.char(...)  -- part 2
local _s3 = string.char(...)  -- part 3
local _s4 = string.char(...)  -- part 4
local _HMAC_SECRET = _s1 .. _s2 .. _s3 .. _s4
```

### Generating char sequences for the secret

Given your secret is e.g. `"mysecret32charstring0000000000ab"`, split into 4×8 chars and convert:

```python
# Python helper to get string.char() calls
secret = "mysecret32charstring0000000000ab"
parts = [secret[i:i+8] for i in range(0, len(secret), 8)]
for p in parts:
    print("string.char(" + ",".join(f"0x{ord(c):02x}" for c in p) + ")")
```

---

## Step 6 — Deploy the Cloudflare Worker

```bash
cd worker
wrangler deploy
```

Note your Worker URL: `https://darkhub-api.YOUR-SUBDOMAIN.workers.dev`

---

## Step 7 — Configure Frontend URLs

Replace `__WORKER_ORIGIN__` in both frontend files:

**On Linux/macOS:**
```bash
WORKER_URL="https://darkhub-api.YOUR-SUBDOMAIN.workers.dev"
sed -i "s|__WORKER_ORIGIN__|$WORKER_URL|g" frontend/callback.html
sed -i "s|__WORKER_ORIGIN__|$WORKER_URL|g" frontend/assets/admin.js
```

**On Windows (PowerShell):**
```powershell
$w = "https://darkhub-api.YOUR-SUBDOMAIN.workers.dev"
(Get-Content frontend\callback.html)  -replace '__WORKER_ORIGIN__', $w | Set-Content frontend\callback.html
(Get-Content frontend\assets\admin.js) -replace '__WORKER_ORIGIN__', $w | Set-Content frontend\assets\admin.js
```

---

## Step 8 — Deploy Frontend to GitHub Pages

1. Create a GitHub repository named `darkhub`
2. Push the `frontend/` directory contents to the `main` branch root (or use a `docs/` folder)
3. Go to **Repository → Settings → Pages → Source: Deploy from branch (main / root)**
4. Your site will be at: `https://YOUR-USERNAME.github.io/darkhub`

### Optional: GitHub Actions auto-deploy

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy Frontend
on:
  push:
    branches: [main]
    paths: ['frontend/**']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Replace worker URL
        run: |
          sed -i "s|__WORKER_ORIGIN__|${{ secrets.WORKER_URL }}|g" frontend/callback.html
          sed -i "s|__WORKER_ORIGIN__|${{ secrets.WORKER_URL }}|g" frontend/assets/admin.js
      - uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./frontend
```

Add `WORKER_URL` as a repository secret in GitHub → Settings → Secrets.

---

## Step 9 — Host hub.lua

The `hub.lua` file must be served from a raw HTTP URL (the players load it via `game:HttpGet`).

**Options:**
- Push it to a **GitHub repository** and use the **raw** URL:
  `https://raw.githubusercontent.com/YOUR-USERNAME/darkhub-scripts/main/hub.lua`
- Or host it directly on your Cloudflare Worker by adding a `/hub` GET route that returns the file contents

> ⚠ **hub.lua source is publicly visible.** The security model accounts for this — secrets are split/encoded, and the actual game scripts are only decrypted in-memory on the client during execution.

---

## Step 10 — Add Scripts via Admin Panel

1. Go to `https://YOUR-USERNAME.github.io/darkhub/admin/`
2. Click **Sign in with GitHub** and authorize with your admin account
3. Navigate to **Scripts → + New Script**
4. Enter: **Name**, **Place ID** (from Roblox), and paste your Luau script source
5. Click **Save Script** — the source is encrypted with AES-256-GCM before storage

---

## Security Checklist

| Item | Status |
|------|--------|
| Secrets set via `wrangler secret put` only | ✅ Required |
| `wrangler.toml` has no real secret values | ✅ Required |
| `HUB_HMAC_SECRET` matches `_HMAC_SECRET` in hub.lua | ✅ Required |
| GitHub OAuth app callback URL matches frontend exactly | ✅ Required |
| `ADMIN_GITHUB_LOGIN` is your exact GitHub username | ✅ Required |
| hub.lua `_HMAC_SECRET` encoded as char sequences | ✅ Recommended |
| hub.lua run through a Lua obfuscator before publish | ✅ Recommended |
| KV namespace IDs updated in `wrangler.toml` | ✅ Required |

---

## Security Model — Honest Assessment

### What IS protected
- ✅ Script source code (stored AES-GCM, transmitted XOR-encrypted)
- ✅ Admin panel (GitHub OAuth + JWT, admin whitelist)
- ✅ Raw API access (HMAC, rate limiting, nonce replay prevention)
- ✅ Naive dump attacks (`writefile`, `getscriptbytecode` hooks)
- ✅ Replay attacks (one-time nonces consumed in KV)

### What is NOT fully protected (fundamental Roblox limitations)
- ⚠ hub.lua source is public (required for `loadstring` delivery)
- ⚠ A skilled attacker who reverse-engineers `_HMAC_SECRET` from hub.lua can forge requests
- ⚠ Roblox's Luau VM can be debugged by sufficiently advanced executor tools
- ⚠ Memory scanning at the OS level can theoretically capture decrypted content

### Recommended mitigations
1. **Obfuscate hub.lua** using a reputable Lua obfuscator before publishing
2. **Rotate `HUB_HMAC_SECRET`** periodically via `wrangler secret put`
3. **Enable Cloudflare Bot Management** on your Worker domain for additional IP reputation filtering

---

## Loader Usage (Players)

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/YOUR-USERNAME/YOUR-REPO/main/hub.lua"))()
```
