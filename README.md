# iOS Security Vulnerability Tracker

An automated system that tracks iOS security vulnerabilities with rich Apple context and CVSS scores, built on Cloudflare's edge platform.

🌐 **Live Demo**: [https://ios.minamoto.me](https://ios.minamoto.me)

## Key Features

- 🔄 **Automated Weekly Scanning**: Scheduled monitoring of Apple security releases
- 🍎 **Rich Apple Context**: Extracts Apple product names, impact analysis, and device compatibility
- 📊 **CVSS Enrichment**: Fetches severity scores from NVD with intelligent rate limiting
- 🌐 **RESTful API**: Dynamic filtering, pagination, and real-time iOS version detection
- 🎨 **Modern Web Interface**: Responsive design with enhanced vulnerability details
- 📈 **Monitoring & Health Checks**: Real-time system status and processing logs

## Architecture

Built on **Cloudflare's Edge Platform**:
- **Workers (API + Cron)**: TypeScript backend (src/index.ts, src/api/handler.ts) serving REST endpoints and a weekly scheduled scan.
- **D1 (Database)**: SQLite-compatible storage for canonical data (vulnerabilities, iOS releases, logs) with migrations.
- **KV (Cache & Telemetry)**: Caches NVD CVSS/description lookups and stores lightweight metrics/alerts with TTLs.
- **Pages (Frontend)**: Static site (`public/`) that calls the Worker API over HTTPS.

Why both D1 and KV?
- D1 is for durable, relational queries (filtering, pagination, stats, integrity checks).
- KV is for fast, globally cached lookups (NVD responses), recent alerts, and simple metrics.

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- Cloudflare account with Workers and D1 enabled
- Wrangler CLI installed globally: `npm install -g wrangler`

### 1. Clone and Install

```bash
git clone <repository-url>
cd ios-security-tracker
npm install
```

### 2. Configure Cloudflare

```bash
# Login to Cloudflare
wrangler login

# Create D1 database
wrangler d1 create ios-vulnerabilities-db

# Create KV namespace
wrangler kv:namespace create "CACHE"
wrangler kv:namespace create "CACHE" --preview
```

### 3. Update Configuration

Update `wrangler.toml` with your database and KV namespace IDs:

```toml
[[d1_databases]]
binding = "DB"
database_name = "ios-vulnerabilities-db"
database_id = "your-database-id-here"

[[kv_namespaces]]
binding = "CACHE"
id = "your-kv-namespace-id-here"
preview_id = "your-preview-kv-namespace-id-here"
```

### 4. Add Secrets (Highly Recommended)

Do NOT store secrets in `wrangler.toml`. Add your NVD API key as a Worker secret:

```bash
npx wrangler secret put NVD_API_KEY
# paste your key when prompted
```

### 5. Deploy

```bash
# Deploy the Worker
npm run deploy

# Deploy the website (optional - can be done via Cloudflare Pages dashboard)
# Set up Cloudflare Pages to deploy from the 'public' directory
```

## API Documentation

### Endpoints

#### GET /api/vulnerabilities
List vulnerabilities with filtering and pagination.

**Query Parameters:**
- `limit` (number, max 100, default 20): Number of results
- `offset` (number, default 0): Pagination offset
- `severity` (string): Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- `search` (string): Search in CVE ID and description
- `ios_version` (string): Filter by iOS version (dynamically populated from database)
- `sort_by` (string): Sort by field (discovered_date, cvss_score, severity, cve_id)
- `sort_order` (string): Sort order (asc, desc)

**Example:**
```bash
curl "https://your-worker.your-subdomain.workers.dev/api/vulnerabilities?severity=CRITICAL&limit=10"
```

#### GET /api/vulnerabilities/{cve_id}
Get specific vulnerability by CVE ID.

**Example:**
```bash
curl "https://your-worker.your-subdomain.workers.dev/api/vulnerabilities/CVE-2024-12345"
```

#### GET /api/vulnerabilities/stats
Get vulnerability statistics.

#### GET /api/releases
List iOS security releases.

#### GET /api/ios-versions
Get available iOS versions from database (for dynamic filtering).

#### GET /api/apple/ios-releases
Discover iOS security release links parsed from Apple’s main page. Optional `major` filter (e.g., `major=18`).

#### GET /api/database/integrity
Check database integrity and duplicate prevention.

#### GET /api/health
System health check with database connectivity and scan status.

#### GET /api/logs
Recent processing logs with detailed execution information.

### Response Format

All API responses follow this structure:

```json
{
  "vulnerabilities": [...],
  "pagination": {
    "total": 150,
    "limit": 50,
    "offset": 0,
    "has_more": true
  },
  "filters": {
    "severity": "HIGH",
    "search": ""
  }
}
```

## Database Schema

The system uses the following main tables:

- **vulnerabilities**: CVE data with CVSS scores and Apple context information
  - Core fields: id, cve_id, description, severity, cvss_score, cvss_vector
  - Apple context: apple_product, apple_impact, apple_description, apple_available_for
  - Metadata: ios_versions_affected, discovered_date, created_at, updated_at
- **ios_releases**: iOS version release information with processing status
- **processing_logs**: Detailed scan execution logs with success/failure tracking
- **vulnerability_releases**: Links vulnerabilities to iOS releases
- **migrations**: Database schema version tracking

## Monitoring

The system includes comprehensive monitoring:

- **Metrics**: Performance and usage metrics stored in KV
- **Alerts**: Automated alerting for system issues
- **Logging**: Structured logging throughout the application
- **Health Checks**: Database connectivity and system status

## Security

- CORS headers configured for API access
- Content Security Policy headers
- Input validation and sanitization
- Rate limiting considerations (NVD lookups are rate-limited and cached; API rate limiting is planned)
- No sensitive data exposure

## Development

### Local Development

```bash
# Start local development server
npm run dev

# Run TypeScript compilation
npm run build

# Lint code
npm run lint

# Format code
npm run format
```

### Testing

The system can be tested locally using Wrangler's development mode:

```bash
# Start with test scheduled events
npx wrangler dev --test-scheduled

# Trigger cron manually
curl "http://localhost:8787/cdn-cgi/handler/scheduled?cron=*+*+*+*+*"
```

## Configuration

### Environment Variables

Set in `wrangler.toml`:

- `ENVIRONMENT`: deployment environment (production/staging)
- `NVD_API_BASE_URL`: NVD API base URL
- `APPLE_SECURITY_BASE_URL`: Apple security page base URL

### Cron Schedule

Current schedule: Every Monday at midnight UTC (`0 0 * * 1`)

To modify, update the `crons` array in `wrangler.toml`.

## Data Sources

- **Apple Security Releases**: https://support.apple.com/en-us/100100
- **NVD API**: https://services.nvd.nist.gov/rest/json/cves/2.0
- **CVE Database**: https://cve.mitre.org/

## Limitations

- NVD API rate limiting (no API key required but requests are limited)
- Apple security page parsing may require updates if page structure changes
- D1 database size limit (10GB per database)
- Worker execution time limits (CPU time and duration)

## Admin & Maintenance

These endpoints are intended for maintenance and require header `X-Admin-Key` (update to your secret):

- `POST /admin/reparse` — force re-parse specific versions with optional `forceUpdate`.
  - Body: `{ "versions": ["18.4.1", "18.3.2"], "forceUpdate": true }`
- `POST /admin/clear-cache` — clear cached URL and data for versions to re-discover and re-ingest.
  - Body: `{ "versions": ["18.4", "18.3"] }`

Note: Re-parse logic performs exact iOS version matching (e.g., 18.1 will not collide with 18.1.1) and validates cached URLs.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Check the logs via `/api/logs` endpoint
- Review health status via `/api/health`
- Check recent alerts for system issues
- Consult Cloudflare Workers documentation for platform-specific issues

## Data Sources

- **Apple Security**: https://support.apple.com/en-us/100100
- **NVD API**: https://services.nvd.nist.gov/rest/json/cves/2.0
- **CVSS Database**: https://www.first.org/cvss/

## Documentation

- [Development Sessions](docs/DEVELOPMENT_SESSIONS.md) - Detailed development history and major improvements
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and debugging steps
- [API Documentation](#api-documentation) - RESTful API endpoints and usage

## Recent Updates

### Version 1.0 - Apple Context Integration ✅

- **Enhanced Apple Context Parsing**: Now extracts rich context from Apple security pages
- **Improved UI/UX**: Visual separation of filters and sorting, precise iOS version matching
- **Manual Reparse System**: Admin tools for data refresh and quality improvement
- **Complete Apple Integration**: Product names, impact analysis, device compatibility

## Roadmap

- [ ] Email/webhook notifications for critical vulnerabilities
- [ ] Historical trend analysis and charts
- [ ] Export functionality (CSV, JSON, PDF)
- [ ] Integration with additional vulnerability databases
- [ ] Advanced search and saved queries

## Changelog (Highlights)

- 2025-09-21
  - Exact iOS version matching: avoids 18.1 vs 18.1.1 collisions; validates cached URLs.
  - Added discovery endpoint: `GET /api/apple/ios-releases` with optional `major` filter.
  - Safe maintenance cleanup (FK-safe `clear-cache` order) and comprehensive iOS 18.x backfill.
  - Moved NVD_API_KEY out of `wrangler.toml` (set via Worker Secret).
