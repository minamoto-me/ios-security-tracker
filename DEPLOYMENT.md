# Deployment Guide

This guide walks through deploying the iOS Security Vulnerability Tracker to Cloudflare.

## 🏆 Recent System Enhancements (2025)

The system has been significantly enhanced with new features:

- ✅ **Enhanced Apple Context Parsing**: Now extracts Apple product names, impact descriptions, fix details, and device compatibility
- ✅ **Dynamic iOS Version Filtering**: Automatically populates filter options based on available data in database
- ✅ **Improved Vulnerability Modal**: Beautiful display of Apple-specific security information with color-coded sections
- ✅ **Database Integrity Monitoring**: Real-time duplicate detection and data validation
- ✅ **Responsive Design Overhaul**: Modern, mobile-first interface with enhanced readability
- ✅ **Robust Error Handling**: Comprehensive undefined value protection and graceful degradation
- ✅ **Exact iOS Version Matching**: Prevents 18.1 from matching 18.1.1; validates cached URLs.
- ✅ **Discovery Endpoint**: `GET /api/apple/ios-releases` to list available releases (supports `?major=18`).
- ✅ **FK-safe Cleanup**: Admin clear-cache now deletes relations first, then data.
- ✅ **Secret Hygiene**: `NVD_API_KEY` moved to Worker Secret (removed from wrangler.toml).

### New API Endpoints
- `/api/ios-versions` - Dynamic iOS version filtering (auto-populated from database)
- `/api/database/integrity` - Database integrity monitoring with duplicate checks

## Prerequisites

- Cloudflare account with Workers and D1 enabled
- Node.js 18+ and npm installed
- Wrangler CLI installed: `npm install -g wrangler`

## Step 1: Initial Setup

### 1.1 Install Dependencies

```bash
npm install
```

### 1.2 Login to Cloudflare

```bash
wrangler login
```

This will open a browser window for authentication.

## Step 2: Create Cloudflare Resources

### 2.1 Create D1 Database

```bash
wrangler d1 create ios-vulnerabilities-db
```

Note the database ID from the output. You'll need it for configuration.

### 2.2 Create KV Namespaces

```bash
# Production namespace
wrangler kv:namespace create "CACHE"

# Preview namespace
wrangler kv:namespace create "CACHE" --preview
```

Note both namespace IDs from the output.

### 2.3 Update wrangler.toml

Edit `wrangler.toml` and replace the placeholder IDs:

```toml
[[d1_databases]]
binding = "DB"
database_name = "ios-vulnerabilities-db"
database_id = "your-actual-database-id-here"

[[kv_namespaces]]
binding = "CACHE"
id = "your-actual-kv-namespace-id-here"
preview_id = "your-actual-preview-kv-namespace-id-here"
```

### 2.4 Add Secrets

Add the NVD API key as a secret — do NOT store in wrangler.toml:

```bash
npx wrangler secret put NVD_API_KEY
# paste your key when prompted
```

## Step 3: Deploy the Worker

### 3.1 Initial Deployment

```bash
npm run deploy
```

This will:
- Compile TypeScript
- Deploy the Worker
- Run database migrations automatically on first request

### 3.2 Verify Deployment

```bash
# Check health endpoint
curl "https://your-worker.your-subdomain.workers.dev/api/health"

# Check API info
curl "https://your-worker.your-subdomain.workers.dev/api"
```

## Step 4: Deploy the Website (Cloudflare Pages)

### 4.1 Via Cloudflare Dashboard

1. Go to Cloudflare Dashboard > Pages
2. Click "Create a project"
3. Connect your Git repository
4. Set build settings:
   - Build command: (leave empty)
   - Build output directory: `public`
   - Root directory: (leave empty)

### 4.2 Via Wrangler (Alternative)

```bash
# Deploy directly from public directory
npx wrangler pages deploy public --project-name ios-security-tracker
```

### 4.3 Configure Custom Domain (Optional)

1. In Pages dashboard, go to your project
2. Click "Custom domains"
3. Add your domain and follow DNS configuration instructions

## Step 5: Configure Scheduled Events

The cron trigger is automatically configured in `wrangler.toml`, but you can verify:

```bash
# Check current cron triggers
wrangler cron ls
```

## Step 6: Test the System

### 6.1 Manual Trigger (Development)

```bash
# For local testing with development server
npx wrangler dev --test-scheduled

# In another terminal, trigger the cron
curl "http://localhost:8787/cdn-cgi/handler/scheduled?cron=*+*+*+*+*"
```

### 6.2 Production Testing

```bash
# Check system health
curl "https://your-worker.your-subdomain.workers.dev/api/health"

# View recent logs
curl "https://your-worker.your-subdomain.workers.dev/api/logs"

# Test API endpoints
curl "https://your-worker.your-subdomain.workers.dev/api/vulnerabilities?limit=5"

# Test new endpoints
curl "https://your-worker.your-subdomain.workers.dev/api/ios-versions"
curl "https://your-worker.your-subdomain.workers.dev/api/database/integrity"
```

## Step 7: Monitoring Setup

### 7.1 Cloudflare Analytics

- Worker analytics are available in the Cloudflare dashboard
- Check request volume, error rates, and performance metrics

### 7.2 Custom Monitoring

The system includes built-in monitoring accessible via API:

```bash
# Check processing logs
curl "https://your-worker.your-subdomain.workers.dev/api/logs"

# Check vulnerability stats
curl "https://your-worker.your-subdomain.workers.dev/api/vulnerabilities/stats"

# Monitor database integrity
curl "https://your-worker.your-subdomain.workers.dev/api/database/integrity"

# Check available iOS versions
curl "https://your-worker.your-subdomain.workers.dev/api/ios-versions"
```

## Step 8: Environment-Specific Configuration

### 8.1 Production Environment

For production deployment, ensure:

```toml
[vars]
ENVIRONMENT = "production"
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json"
APPLE_SECURITY_BASE_URL = "https://support.apple.com"
```

### 8.2 Staging Environment

For staging, you might want separate resources:

```bash
# Create staging database
wrangler d1 create ios-vulnerabilities-db-staging

# Create staging KV namespace
wrangler kv:namespace create "CACHE-STAGING"
```

## Troubleshooting

### Common Issues

#### 1. Database Not Found
```
Error: D1_ERROR: no such table: vulnerabilities
```
**Solution**: The database migrations should run automatically on first request. If not, check the logs.

#### 2. KV Namespace Binding Error
```
Error: The binding "CACHE" is not defined
```
**Solution**: Ensure KV namespace IDs are correctly set in `wrangler.toml`.

#### 3. Cron Not Triggering
**Solution**: Cron triggers can take up to 15 minutes to propagate after deployment.

#### 4. NVD API Rate Limiting
```
Error: NVD API error: 429 Too Many Requests
```
**Solution**: The system includes built-in rate limiting and retry logic. This is normal behavior.

### Logs and Debugging

#### View Worker Logs
```bash
wrangler tail
```

#### Check Database Contents
```bash
# List tables
wrangler d1 execute ios-vulnerabilities-db --command "SELECT name FROM sqlite_master WHERE type='table'"

# Check vulnerability count
wrangler d1 execute ios-vulnerabilities-db --command "SELECT COUNT(*) FROM vulnerabilities"
```

#### View KV Contents
```bash
# List keys
wrangler kv:key list --namespace-id="your-namespace-id"

# Get specific value
wrangler kv:key get "nvd:cvss:CVE-2024-12345" --namespace-id="your-namespace-id"
```

## Security Considerations

### 1. API Access
- The API is publicly accessible with CORS enabled
- No authentication is implemented by default
- Consider adding API keys for production use

### 2. Rate Limiting
- Built-in rate limiting for NVD API calls
- Consider implementing API rate limiting for your endpoints

### 3. Data Privacy
- No personal data is stored
- All vulnerability data is public information
- Logs may contain IP addresses (consider Cloudflare's data retention policies)

## Performance Optimization

### 1. Caching
- NVD API responses are cached in KV for 24 hours
- Consider implementing response caching for API endpoints

### 2. Database
- Indexes are configured for common queries
- Consider partitioning large tables if needed

### 3. Worker Optimization
- Bundle size is optimized for fast cold starts
- Database connections are reused within requests

## Maintenance

### Regular Tasks

1. **Monitor Logs**: Check processing logs weekly
2. **Review Metrics**: Check vulnerability trends and system performance
3. **Update Dependencies**: Keep npm packages updated
4. **Backup Data**: D1 includes automatic backups, but consider additional backup strategies

### Updates

To deploy updates:

```bash
# Deploy code changes
npm run deploy

# Update database schema (if needed)
# Migrations run automatically on deployment
```

## Cost Estimation

Cloudflare Workers pricing (as of 2025):

- **Workers**: Free tier includes 100,000 requests/day
- **D1**: Free tier includes 25 million row reads/month
- **KV**: Free tier includes 100,000 reads/day
- **Pages**: Free tier includes unlimited requests

For most use cases, this system will operate within free tier limits.

## Backup and Recovery

### Database Backup
```bash
# Export all data
wrangler d1 export ios-vulnerabilities-db --output backup.sql
```

### KV Backup
```bash
# List and backup critical keys
wrangler kv:key list --namespace-id="your-namespace-id" > kv-keys.txt
```

### Recovery
```bash
# Restore database
wrangler d1 execute ios-vulnerabilities-db --file backup.sql
```

This completes the deployment guide. The system should now be fully operational and scanning for iOS vulnerabilities weekly.
