# Troubleshooting Guide

This guide covers common issues and debugging steps for the iOS Security Vulnerability Tracker.

## Common Issues

### Apple Context Parsing Not Working

**Symptoms**:
- Apple fields (apple_product, apple_impact, etc.) are null in the database
- Manual scans complete but don't populate Apple context
- Vulnerabilities only have basic description without Apple details

**Debugging Steps**:

1. **Check Apple Security Page Structure**:
   ```bash
   # Fetch a sample page and check HTML structure
   curl -s "https://support.apple.com/en-us/125108" | grep -A 5 -B 5 "gb-header"
   ```

2. **Test Parser Directly**:
   ```bash
   # Test the Apple parser with a known page
   curl -X POST "https://your-worker.workers.dev/api/test-apple-parser"
   ```

3. **Check Processing Logs**:
   ```bash
   # View recent scan logs
   curl "https://your-worker.workers.dev/api/logs"
   ```

4. **Manual Reparse**:
   ```bash
   # Force reparse of specific versions
   curl -X POST "https://your-worker.workers.dev/admin/reparse" \
     -H "Content-Type: application/json" \
     -H "X-Admin-Key: manual-reparse-2024" \
     -d '{"versions": ["26"], "forceUpdate": true}'
  ```

### Exact Version Confusion (e.g., 18.1 vs 18.1.1)

**Symptoms**:
- 18.1 data appears under 18.1.1 (or vice versa)

**Status**: Fixed — parser now enforces exact iOS version matches and validates cached URLs.

**Recovery**:
1. Clear data for the affected versions (FK-safe order is built-in):
   ```bash
   curl -X POST "https://your-worker.workers.dev/admin/clear-cache" \
     -H "Content-Type: application/json" \
     -H "X-Admin-Key: manual-reparse-2024" \
     -d '{"versions": ["18.1", "18.1.1"]}'
   ```
2. Force reparse with exact match logic:
   ```bash
   curl -X POST "https://your-worker.workers.dev/admin/reparse" \
     -H "Content-Type: application/json" \
     -H "X-Admin-Key: manual-reparse-2024" \
     -d '{"versions": ["18.1", "18.1.1"], "forceUpdate": true}'
   ```

### Missing iOS Versions

**Find what Apple exposes**:
```bash
curl "https://your-worker.workers.dev/api/apple/ios-releases?major=18"
```
Then reparse specific versions as needed via `/admin/reparse`.

### NVD API Rate Limiting

**Symptoms**:
- CVSS scores are missing (null values)
- Processing logs show NVD API errors
- Slow or failed vulnerability enrichment

**Solutions**:
1. **Check Rate Limiting**: The system has built-in delays (100ms between requests)
2. **Monitor API Health**: Check NVD API status at https://nvd.nist.gov/
3. **Retry Failed CVEs**: Use manual reparse to retry failed lookups
4. **Use Secrets**: Store `NVD_API_KEY` as a Worker Secret (no plaintext in wrangler.toml)

### Database Connection Issues

**Symptoms**:
- Health check endpoint returns "unhealthy"
- Database queries fail with connection errors
- Worker throws D1 database errors

**Debugging Steps**:
1. **Check Health Endpoint**:
   ```bash
   curl "https://your-worker.workers.dev/api/health"
   ```

2. **Verify D1 Configuration**:
   - Check `wrangler.toml` database binding
   - Ensure database ID is correct
   - Verify permissions in Cloudflare dashboard

3. **Test Database Integrity**:
   ```bash
   curl "https://your-worker.workers.dev/api/database/integrity"
   ```

### Scheduled Cron Job Not Running

**Symptoms**:
- No new vulnerabilities appearing
- Processing logs show no recent runs
- Last scan timestamp is old

**Debugging Steps**:
1. **Check Cron Configuration** in `wrangler.toml`:
   ```toml
   [triggers]
   crons = ["0 0 * * 1"]  # Every Monday at midnight UTC
   ```

2. **Manual Trigger**:
   ```bash
   curl -X POST "https://your-worker.workers.dev/api/scan/trigger"
   ```

3. **Check Worker Logs** in Cloudflare dashboard under Workers & Pages > your-worker > Logs

### Frontend Not Updating

**Symptoms**:
- Website shows outdated information
- UI changes not visible
- Data from API is current but website isn't

**Solution**:
- Frontend and backend are deployed separately
- Backend: Cloudflare Workers (via `npm run deploy`)
- Frontend: Cloudflare Pages (separate deployment)

**Fix**:
1. **Deploy Frontend**:
   ```bash
   # Deploy to Cloudflare Pages
   npx wrangler pages deploy public --project-name=ios-security-tracker
   ```

2. **Check Current Deployments**:
   - Backend: https://your-worker.workers.dev
   - Frontend: https://your-pages.pages.dev

### Memory or Timeout Issues

**Symptoms**:
- Worker exits with timeout errors
- Memory limit exceeded errors
- Incomplete processing of large vulnerability sets

**Solutions**:
1. **Reduce Batch Size**: Process fewer vulnerabilities per run
2. **Add More Rate Limiting**: Increase delays between API calls
3. **Split Processing**: Process different iOS versions in separate runs

## Environment-Specific Issues

### Local Development

**Common Issues**:
- Environment variables not set
- Database not accessible locally
- CORS issues during development

**Solutions**:
1. **Use Wrangler Dev**:
   ```bash
   npx wrangler dev --local
   ```

2. **Test with Remote Database**:
   ```bash
   npx wrangler dev --remote
   ```

### Production Deployment

**Common Issues**:
- Binding configuration mismatch
- Environment variables not set correctly
- Domain routing problems

**Check List**:
1. ✅ `wrangler.toml` configuration matches Cloudflare dashboard
2. ✅ D1 database exists and has correct schema
3. ✅ KV namespace exists for caching
4. ✅ Environment variables and Secrets are set correctly (e.g., `NVD_API_KEY` via Secret)
5. ✅ Custom domain (if any) points to correct Worker

## Monitoring and Alerting

### Health Check Endpoints

Use these endpoints for monitoring:

1. **System Health**: `GET /api/health`
   - Database connectivity
   - Last scan status
   - Basic system metrics

2. **Database Integrity**: `GET /api/database/integrity`
   - Duplicate detection
   - Data validation
   - Table counts

3. **Processing Logs**: `GET /api/logs`
   - Recent scan results
   - Error tracking
   - Performance metrics

### Setting Up Monitoring

1. **External Monitoring**: Point health check services to `/api/health`
2. **Cloudflare Analytics**: Monitor Worker performance in dashboard
3. **Custom Alerts**: Set up notifications based on health check responses

## Emergency Procedures

### System Recovery

If the system is completely down:

1. **Check Worker Status** in Cloudflare dashboard
2. **Verify Database Connectivity** via health endpoint
3. **Review Recent Deployments** and rollback if needed
4. **Check Processing Logs** for error patterns

### Data Recovery

If data is corrupted or lost:

1. **Database Backup**: D1 doesn't have automatic backups
2. **Re-scan Data**: Use manual reparse to rebuild from sources
3. **Emergency Data**: Sample data endpoint can populate test data

### Performance Issues

If the system is slow or timing out:

1. **Reduce Processing Load**: Limit vulnerability processing batch size
2. **Increase Rate Limiting**: Add more delays between API calls
3. **Split Work**: Process different data sources separately
4. **Monitor Resource Usage**: Check Worker CPU and memory usage

## Getting Help

1. **Check Logs**: Always start with `/api/logs` and `/api/health`
2. **Review Documentation**: Check API documentation and schema
3. **Cloudflare Support**: For platform-specific issues
4. **Community**: For general Workers/D1 questions
