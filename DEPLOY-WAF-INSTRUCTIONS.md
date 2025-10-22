# Deploy WAF Rules to Cloudflare

## Quick Instructions (5 minutes)

### 1. Access Cloudflare Dashboard

1. Go to https://dash.cloudflare.com
2. Select your domain/worker
3. Navigate to **Security** → **WAF**

### 2. Deploy WAF Rules

Use the configuration from [`cloudflare-waf-config.json`](cloudflare-waf-config.json)

**Option A: via Cloudflare Dashboard (Manual - 5 min)**

For each rule in the JSON:

1. Click "Create rule"
2. Set rule name
3. Add expression from JSON
4. Set action (Block/Challenge/Managed Challenge)
5. Click "Deploy"

**Option B: via API (Automated - 2 min)**

```bash
# Get your Cloudflare API token
# Dashboard → My Profile → API Tokens → Create Token

# Set zone ID (from your dashboard)
ZONE_ID="your_zone_id_here"
API_TOKEN="your_api_token_here"

# Deploy all rules
curl -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint" \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @cloudflare-waf-config.json
```

### 3. Enable Rate Limiting

Use configuration from [`rate-limiting-config.json`](rate-limiting-config.json)

1. Navigate to **Security** → **Rate Limiting Rules**
2. Click "Create rule"
3. Configure tiers:
   - **Unauthenticated:** 30 requests/minute
   - **Authenticated:** 100 requests/minute
   - **Premium users:** 500 requests/minute
4. Save and deploy

### 4. Verify Deployment

Test that rules are working:

```bash
# Test SQL injection blocking
curl -X POST https://your-worker.workers.dev/api/v1/test \
  -d "username=admin' OR '1'='1"

# Should return: 403 Forbidden

# Test rate limiting
for i in {1..35}; do
  curl https://your-worker.workers.dev/api/v1/health
done

# Should be rate limited after 30 requests
```

### 5. Monitor & Adjust

1. Go to **Analytics** → **Security**
2. Review blocked requests
3. Adjust rules as needed
4. Monitor false positives

---

## Detailed WAF Rules

### Rule 1: SQL Injection Prevention
```
(http.request.uri.query contains "' OR" or
 http.request.uri.query contains "UNION SELECT" or
 http.request.body.raw contains "' OR" or
 http.request.body.raw contains "UNION SELECT")
```
**Action:** Block

### Rule 2: XSS Prevention
```
(http.request.uri.query contains "<script" or
 http.request.body.raw contains "<script")
```
**Action:** Block

### Rule 3: Path Traversal
```
(http.request.uri.path contains "../" or
 http.request.uri.path contains "..\\")
```
**Action:** Block

### Rule 4: Admin Panel Protection
```
(http.request.uri.path contains "/admin" and
 not ip.src in {YOUR_OFFICE_IP})
```
**Action:** Challenge

### Rule 5: API Rate Limiting
```
(http.request.uri.path contains "/api" and
 rate(1m) > 100)
```
**Action:** Block

---

## Priority Order

1. SQL Injection (highest priority)
2. XSS Prevention
3. Path Traversal
4. Admin Protection
5. Rate Limiting
6. Bot Detection
7. DDoS Protection
8. Suspicious Patterns
9. Country Blocking (if needed)
10. General Security (lowest priority)

---

## Testing Checklist

- [ ] SQL injection attempts are blocked
- [ ] XSS attempts are blocked
- [ ] Path traversal blocked
- [ ] Rate limiting works
- [ ] Legitimate traffic passes through
- [ ] No false positives on real users
- [ ] Challenge pages work correctly
- [ ] Analytics show rule triggers

---

## Rollback Plan

If something goes wrong:

```bash
# Disable all WAF rules immediately
curl -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint" \
  -H "Authorization: Bearer ${API_TOKEN}"
```

Or via dashboard:
1. Security → WAF
2. Click rule
3. Click "Disable" or "Delete"

---

## Next Steps After Deployment

1. Monitor Security Analytics for 24 hours
2. Review blocked requests
3. Whitelist any false positives
4. Fine-tune rule sensitivity
5. Set up alerting for rule triggers
6. Document any custom adjustments

---

## Support

- Cloudflare WAF Docs: https://developers.cloudflare.com/waf/
- Rate Limiting: https://developers.cloudflare.com/waf/rate-limiting-rules/
- Security Analytics: https://developers.cloudflare.com/analytics/security/

**Questions?** Check `monitoring/PRODUCTION-RUNBOOK.md` for incident response procedures.
