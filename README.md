# iOS Security Vulnerability Tracker

An automated system built with Cloudflare Workers that tracks iOS security vulnerabilities, enriches them with CVSS scores, and presents them on a public website.

## Features

- 🔄 **Automated Weekly Scanning**: Scheduled cron job runs every Monday to scan for new iOS vulnerabilities
- 🍎 **Enhanced Apple Security Integration**: Parses Apple's security release pages with full context extraction
  - **Apple Product Information**: Extracts specific Apple products affected (e.g., "Apple Neural Engine", "CoreMedia", "Safari")
  - **Impact Analysis**: Security implications for users from Apple's assessments
  - **Fix Descriptions**: How Apple addressed each vulnerability
  - **Device Compatibility**: Which devices and iOS versions are affected
- 📊 **CVSS Enrichment**: Fetches CVSS scores and vectors from NVD API with intelligent rate limiting
- 🗄️ **Robust Data Storage**: Uses Cloudflare D1 database with duplicate prevention and integrity checks
- 🌐 **Dynamic Public API**: RESTful API with smart filtering, pagination, and real-time iOS version detection
- 🎨 **Modern Responsive Web Interface**: Beautiful, mobile-optimized website with enhanced vulnerability modals
- 📈 **Comprehensive Monitoring**: Real-time health checks, database integrity monitoring, and processing logs
- ⚡ **High Performance**: Global CDN distribution via Cloudflare with optimized caching

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

## Recent Achievements (2025)

### ✅ Session 3: Apple Context Parsing Fix (September 21, 2025)

**BREAKTHROUGH: Successfully Fixed Apple Context Parsing**
- **Problem Identified**: The Apple security page parsing was completely failing due to incorrect HTML structure assumptions
- **Root Cause**: Code was looking for CVE patterns embedded in paragraph text, but Apple's actual structure uses section-based organization
- **Solution Implemented**: Complete rewrite of parsing logic to match Apple's actual HTML structure:
  ```
  <h3 class="gb-header">Product Name</h3> (e.g., "WebKit", "Kernel", "Apple Neural Engine")
  <p class="gb-paragraph">Available for: ...</p> (device compatibility)
  <p class="gb-paragraph">Impact: ...</p> (security implications)
  <p class="gb-paragraph">Description: ...</p> (how Apple fixed it)
  <p class="gb-paragraph">CVE-XXXX-XXXX: researcher</p> (CVE ID)
  ```

**Results**:
- ✅ 42 vulnerabilities successfully parsed with complete Apple context
- ✅ All Apple-specific fields now populated (product, impact, description, device compatibility)
- ✅ 3 iOS releases processed (iOS 26, iOS 18.7, iOS 16.7.12)
- ✅ Database and website now displaying rich Apple security context

### ✅ Previous Achievements

- ✅ **Enhanced Apple Context Parsing**: Now extracts Apple product names, impact descriptions, fix details, and device compatibility
- ✅ **Dynamic iOS Version Filtering**: Automatically populates filter options based on available data in database
- ✅ **Improved Vulnerability Modal**: Beautiful display of Apple-specific security information with color-coded sections
- ✅ **Database Integrity Monitoring**: Real-time duplicate detection and data validation
- ✅ **Responsive Design Overhaul**: Modern, mobile-first interface with enhanced readability
- ✅ **Robust Error Handling**: Comprehensive undefined value protection and graceful degradation

## Roadmap

- [ ] Email/webhook notifications for critical vulnerabilities
- [ ] Historical trend analysis and vulnerability timeline charts
- [ ] CVE severity score predictions using machine learning
- [ ] Integration with additional vulnerability databases (MITRE, GitHub Security Advisory)
- [ ] Advanced search with regex support and saved searches
- [ ] Export functionality (CSV, JSON, PDF reports)
- [ ] Real-time vulnerability feed subscriptions with webhooks

## Development Notes & Troubleshooting

### Apple Security Page Structure (as of September 2025)

The Apple security pages follow a consistent structure that the parser relies on:

1. **Main List Page**: `https://support.apple.com/en-us/100100`
   - Contains a table with links to individual security bulletins
   - Links follow pattern: `/en-us/XXXXXX` (e.g., `/en-us/125108` for iOS 26)

2. **Individual Security Pages**: Each page has sections like:
   ```html
   <h3 class="gb-header">Product Name</h3>
   <p class="gb-paragraph">Available for: device list</p>
   <p class="gb-paragraph">Impact: security implications</p>
   <p class="gb-paragraph">Description: how Apple fixed it</p>
   <p class="gb-paragraph">CVE-XXXX-XXXX: researcher credit</p>
   ```

### Debugging Apple Context Parsing

If Apple context parsing fails again:

1. **Check the HTML structure**: Use curl to fetch a sample page:
   ```bash
   curl -s "https://support.apple.com/en-us/125108" | grep -A 10 -B 5 "gb-header"
   ```

2. **Verify section parsing**: The regex pattern expects `<h3 class="gb-header">` elements
   - If Apple changes CSS classes, update the pattern in `extractFieldFromSection()`

3. **Test manual scan**: Use the API endpoint to trigger manual scanning:
   ```bash
   curl -X POST "https://your-worker.workers.dev/api/scan/trigger"
   ```

4. **Check processing logs**: View recent scan results:
   ```bash
   curl "https://your-worker.workers.dev/api/logs"
   ```

### Known Limitations & Future Improvements

1. **HTML Structure Dependency**: Parser relies on Apple's specific CSS classes and structure
   - **Risk**: Apple could change their page structure
   - **Mitigation**: Regular monitoring and fallback parsing methods

2. **Rate Limiting**: NVD API has rate limits for CVSS score enrichment
   - **Current**: Built-in rate limiting and caching
   - **Future**: Consider getting an NVD API key for higher limits

3. **Error Handling**: Current parser is robust but could be enhanced
   - **Future**: Add more detailed error reporting and automatic retry logic

### Session History

- **Session 1**: Initial implementation with basic Apple parsing
- **Session 2**: Enhanced UI, dynamic filtering, database integrity monitoring
- **Session 3**: **MAJOR FIX** - Corrected Apple parsing logic based on actual HTML structure analysis