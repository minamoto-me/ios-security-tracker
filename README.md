# iOS Security Vulnerability Tracker

An automated system built with Cloudflare Workers that tracks iOS security vulnerabilities, enriches them with CVSS scores, and presents them on a public website.

## Features

- 🔄 **Automated Weekly Scanning**: Scheduled cron job runs every Monday to scan for new iOS vulnerabilities
- 🍎 **Apple Security Integration**: Parses Apple's security release pages for iOS vulnerabilities
- 📊 **CVSS Enrichment**: Fetches CVSS scores and vectors from NVD API
- 🗄️ **Persistent Storage**: Uses Cloudflare D1 database for structured data storage
- 🌐 **Public API**: RESTful API with filtering, pagination, and search capabilities
- 🎨 **Modern Web Interface**: Responsive website for browsing vulnerabilities
- 📈 **Monitoring & Alerts**: Comprehensive logging and alerting system
- ⚡ **High Performance**: Global CDN distribution via Cloudflare

## Architecture

- **Backend**: Cloudflare Workers (TypeScript)
- **Database**: Cloudflare D1 (SQLite-compatible)
- **Cache**: Cloudflare Workers KV
- **Frontend**: Static HTML/CSS/JavaScript hosted on Cloudflare Pages
- **Deployment**: Wrangler CLI

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

### 4. Deploy

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
- `limit` (number, max 100, default 50): Number of results
- `offset` (number, default 0): Pagination offset
- `severity` (string): Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- `search` (string): Search in CVE ID and description

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

#### GET /api/health
System health check.

#### GET /api/logs
Recent processing logs.

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

- **vulnerabilities**: CVE data with CVSS scores
- **ios_releases**: iOS version release information
- **processing_logs**: Scan execution logs
- **vulnerability_releases**: Links vulnerabilities to iOS releases

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
- Rate limiting considerations
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

## Roadmap

- [ ] Email/webhook notifications for critical vulnerabilities
- [ ] Historical trend analysis
- [ ] CVE severity score predictions
- [ ] Integration with additional vulnerability databases
- [ ] Enhanced search and filtering capabilities
- [ ] Export functionality (CSV, JSON)
- [ ] Vulnerability feed subscriptions