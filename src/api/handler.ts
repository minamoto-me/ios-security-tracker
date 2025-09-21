import { Env, Vulnerability } from '../types';
import { VulnerabilityRepository } from '../database/repository';

export class ApiHandler {
  private repository: VulnerabilityRepository;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.repository = new VulnerabilityRepository(env);
  }

  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Add CORS headers for all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json',
    };

    // Handle preflight OPTIONS requests
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      // Route requests
      if (method === 'GET') {
        if (path === '/api/vulnerabilities') {
          return await this.getVulnerabilities(url, corsHeaders);
        }
        if (path === '/api/vulnerabilities/stats') {
          return await this.getVulnerabilityStats(corsHeaders);
        }
        if (path.startsWith('/api/vulnerabilities/')) {
          const cveId = path.split('/').pop();
          if (cveId) {
            return await this.getVulnerability(cveId, corsHeaders);
          }
        }
        if (path === '/api/releases') {
          return await this.getIOSReleases(corsHeaders);
        }
        if (path === '/api/ios-versions') {
          return await this.getAvailableIOSVersions(corsHeaders);
        }
        if (path === '/api/database/integrity') {
          return await this.checkDatabaseIntegrity(corsHeaders);
        }
        if (path === '/api/logs') {
          return await this.getProcessingLogs(corsHeaders);
        }
        if (path === '/api/health') {
          return await this.getHealthCheck(corsHeaders);
        }
        if (path === '/api/apple/ios-releases') {
          return await this.getDiscoveredIOSReleases(new URL(request.url), corsHeaders);
        }
        if (path === '/' || path === '/api') {
          return await this.getApiInfo(corsHeaders);
        }
      }

      if (method === 'POST' && path === '/api/scan/trigger') {
        return await this.triggerManualScan(corsHeaders);
      }

      if (method === 'POST' && path === '/api/populate-sample-data') {
        return await this.populateSampleData(corsHeaders);
      }

      if (method === 'POST' && path === '/api/test-apple-parser') {
        return await this.testAppleParser(corsHeaders);
      }

      if (method === 'POST' && path === '/api/test-apple-links') {
        return await this.testAppleLinksParser(corsHeaders);
      }

      if (method === 'POST' && path === '/api/process-latest-ios') {
        return await this.processLatestIOS(corsHeaders);
      }

      if (method === 'POST' && path === '/api/debug-full-scan') {
        return await this.debugFullScan(corsHeaders);
      }

      if (method === 'POST' && path === '/api/test-latest-versions') {
        return await this.testLatestVersions(corsHeaders);
      }

      if (method === 'POST' && path === '/api/process-all-latest-cves') {
        return await this.processAllLatestCVEs(corsHeaders);
      }

      if (method === 'POST' && path === '/admin/reparse') {
        return await this.manualReparse(request, corsHeaders);
      }

      if (method === 'POST' && path === '/admin/clear-cache') {
        return await this.clearCachedUrls(request, corsHeaders);
      }

      // Not found
      return new Response(
        JSON.stringify({ error: 'Not found', path }),
        { status: 404, headers: corsHeaders }
      );

    } catch (error) {
      console.error('API error:', error);
      return new Response(
        JSON.stringify({
          error: 'Internal server error',
          message: error instanceof Error ? error.message : 'Unknown error',
        }),
        { status: 500, headers: corsHeaders }
      );
    }
  }

  private async getVulnerabilities(url: URL, headers: Record<string, string>): Promise<Response> {
    const searchParams = url.searchParams;
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
    const offset = Math.max(parseInt(searchParams.get('offset') || '0'), 0);
    const severity = searchParams.get('severity') || undefined;
    const search = searchParams.get('search') || undefined;
    const iosVersion = searchParams.get('ios_version') || undefined;
    const sortBy = searchParams.get('sort_by') || 'discovered_date';
    const sortOrder = searchParams.get('sort_order') || 'desc';

    const [vulnerabilities, total] = await Promise.all([
      this.repository.getAllVulnerabilities(limit, offset, severity, search, iosVersion, sortBy, sortOrder),
      this.repository.getVulnerabilityCount(severity, search, iosVersion),
    ]);

    const response = {
      vulnerabilities,
      pagination: {
        total,
        limit,
        offset,
        has_more: offset + limit < total,
      },
      filters: {
        severity,
        search,
        ios_version: iosVersion,
        sort_by: sortBy,
        sort_order: sortOrder,
      },
    };

    return new Response(JSON.stringify(response), { headers });
  }

  private async getVulnerability(cveId: string, headers: Record<string, string>): Promise<Response> {
    const vulnerability = await this.repository.getVulnerabilityByCveId(cveId);

    if (!vulnerability) {
      return new Response(
        JSON.stringify({ error: 'Vulnerability not found', cve_id: cveId }),
        { status: 404, headers }
      );
    }

    return new Response(JSON.stringify({ vulnerability }), { headers });
  }

  private async getVulnerabilityStats(headers: Record<string, string>): Promise<Response> {
    const stats = await this.repository.getVulnerabilityStats();
    return new Response(JSON.stringify({ stats }), { headers });
  }

  private async getIOSReleases(headers: Record<string, string>): Promise<Response> {
    const releases = await this.repository.getAllIOSReleases();
    return new Response(JSON.stringify({ releases }), { headers });
  }

  private async getProcessingLogs(headers: Record<string, string>): Promise<Response> {
    const logs = await this.repository.getRecentProcessingLogs();
    return new Response(JSON.stringify({ logs }), { headers });
  }

  private async getHealthCheck(headers: Record<string, string>): Promise<Response> {
    try {
      // Test database connectivity
      const stats = await this.repository.getVulnerabilityStats();
      const recentLogs = await this.repository.getRecentProcessingLogs(1);

      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: {
          connected: true,
          total_vulnerabilities: stats.total,
        },
        last_scan: recentLogs.length > 0 ? {
          date: recentLogs[0].run_date,
          status: recentLogs[0].status,
          vulnerabilities_found: recentLogs[0].vulnerabilities_found,
        } : null,
      };

      return new Response(JSON.stringify(health), { headers });

    } catch (error) {
      const health = {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };

      return new Response(
        JSON.stringify(health),
        { status: 503, headers }
      );
    }
  }

  private async getApiInfo(headers: Record<string, string>): Promise<Response> {
    const info = {
      name: 'iOS Security Vulnerability Tracker API',
      version: '1.0.0',
      description: 'API for tracking iOS security vulnerabilities with CVSS scores',
      endpoints: {
        vulnerabilities: {
          'GET /api/vulnerabilities': 'List vulnerabilities with filtering and pagination',
          'GET /api/vulnerabilities/stats': 'Get vulnerability statistics',
          'GET /api/vulnerabilities/{cve_id}': 'Get specific vulnerability by CVE ID',
        },
        releases: {
          'GET /api/releases': 'List iOS security releases',
        },
        system: {
          'GET /api/health': 'System health check',
          'GET /api/logs': 'Recent processing logs',
          'POST /api/scan/trigger': 'Manually trigger vulnerability scan',
        },
      },
      query_parameters: {
        vulnerabilities: {
          limit: 'Number of results (max 100, default 50)',
          offset: 'Pagination offset (default 0)',
          severity: 'Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)',
          search: 'Search in CVE ID and description',
        },
      },
      last_updated: new Date().toISOString(),
    };

    return new Response(JSON.stringify(info, null, 2), { headers });
  }

  private async triggerManualScan(headers: Record<string, string>): Promise<Response> {
    try {
      // Import the VulnerabilityScanner
      const { VulnerabilityScanner } = await import('../services/vulnerability-scanner');

      const startTime = Date.now();
      console.log('Manual vulnerability scan started at:', new Date().toISOString());

      // Create and run vulnerability scanner
      const scanner = new VulnerabilityScanner(this.env);
      const scanResult = await scanner.runWeeklyVulnerabilityScan();

      const executionTime = Date.now() - startTime;
      console.log(`Manual scan completed successfully in ${executionTime}ms`);
      console.log('Scan results:', scanResult);

      const response = {
        message: 'Manual scan completed successfully',
        execution_time_ms: executionTime,
        scan_results: scanResult,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), { headers });

    } catch (error) {
      console.error('Manual scan failed:', error);

      const response = {
        message: 'Manual scan failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async populateSampleData(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Populating sample vulnerability data...');

      // Sample vulnerabilities based on real iOS CVEs
      const sampleVulnerabilities: Omit<Vulnerability, 'created_at'>[] = [
        {
          id: 'CVE-2024-44308',
          cve_id: 'CVE-2024-44308',
          description: 'A buffer overflow issue was addressed with improved memory handling.',
          severity: 'HIGH',
          cvss_score: 7.8,
          cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
          ios_versions_affected: 'iOS 18.1',
          discovered_date: '2024-10-28',
        },
        {
          id: 'CVE-2024-44309',
          cve_id: 'CVE-2024-44309',
          description: 'A memory corruption issue was addressed with improved input validation.',
          severity: 'CRITICAL',
          cvss_score: 9.8,
          cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          ios_versions_affected: 'iOS 18.1',
          discovered_date: '2024-10-28',
        },
        {
          id: 'CVE-2024-44310',
          cve_id: 'CVE-2024-44310',
          description: 'An out-of-bounds read issue was addressed with improved bounds checking.',
          severity: 'MEDIUM',
          cvss_score: 5.5,
          cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
          ios_versions_affected: 'iOS 18.0, iOS 17.7',
          discovered_date: '2024-09-16',
        },
        {
          id: 'CVE-2024-40866',
          cve_id: 'CVE-2024-40866',
          description: 'A logic issue was addressed with improved state management.',
          severity: 'HIGH',
          cvss_score: 8.1,
          cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
          ios_versions_affected: 'iOS 17.6',
          discovered_date: '2024-07-29',
        },
        {
          id: 'CVE-2024-40857',
          cve_id: 'CVE-2024-40857',
          description: 'A use-after-free issue was addressed with improved memory management.',
          severity: 'CRITICAL',
          cvss_score: 9.8,
          cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          ios_versions_affected: 'iOS 17.6',
          discovered_date: '2024-07-29',
        },
      ];

      let inserted = 0;
      for (const vuln of sampleVulnerabilities) {
        try {
          await this.repository.insertVulnerability(vuln);
          inserted++;
          console.log(`Inserted vulnerability: ${vuln.cve_id}`);
        } catch (error) {
          console.warn(`Failed to insert ${vuln.cve_id}:`, error);
        }
      }

      // Also insert some iOS releases
      const sampleReleases = [
        {
          version: '18.1',
          release_date: '2024-10-28',
          security_content_url: 'https://support.apple.com/en-us/121238',
        },
        {
          version: '18.0',
          release_date: '2024-09-16',
          security_content_url: 'https://support.apple.com/en-us/121250',
        },
        {
          version: '17.7',
          release_date: '2024-09-16',
          security_content_url: 'https://support.apple.com/en-us/121251',
        },
        {
          version: '17.6',
          release_date: '2024-07-29',
          security_content_url: 'https://support.apple.com/en-us/121234',
        },
      ];

      let releasesInserted = 0;
      for (const release of sampleReleases) {
        try {
          await this.repository.insertIOSRelease(release);
          releasesInserted++;
          console.log(`Inserted iOS release: ${release.version}`);
        } catch (error) {
          console.warn(`Failed to insert iOS ${release.version}:`, error);
        }
      }

      const response = {
        message: 'Sample data populated successfully',
        vulnerabilities_inserted: inserted,
        releases_inserted: releasesInserted,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), { headers });

    } catch (error) {
      console.error('Failed to populate sample data:', error);

      const response = {
        message: 'Failed to populate sample data',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async testAppleParser(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Testing Apple security page parser...');

      // Import the AppleSecurityParser
      const { AppleSecurityParser } = await import('../services/apple-security-parser');

      // Test with the same page you used in Python: HT122066
      const testUrl = 'https://support.apple.com/en-us/122066';

      console.log(`Fetching Apple security page: ${testUrl}`);
      const response = await fetch(testUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch ${testUrl}: ${response.status}`);
      }

      const html = await response.text();
      console.log(`Fetched ${html.length} characters from Apple security page`);

      // Parse the security content
      const parsedData = AppleSecurityParser.parseSecurityContent(html, '18.1');

      const result = {
        message: 'Apple parser test completed',
        test_url: testUrl,
        html_length: html.length,
        vulnerabilities_found: parsedData.vulnerabilities.length,
        vulnerabilities: parsedData.vulnerabilities,
        release_date: parsedData.releaseDate,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(result, null, 2), { headers });

    } catch (error) {
      console.error('Apple parser test failed:', error);

      const response = {
        message: 'Apple parser test failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async testAppleLinksParser(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Testing Apple security links parser...');

      // Import the VulnerabilityScanner to access the link extraction method
      const { VulnerabilityScanner } = await import('../services/vulnerability-scanner');

      // Test with main Apple security page
      const testUrl = 'https://support.apple.com/en-us/100100';

      console.log(`Fetching Apple main security page: ${testUrl}`);
      const response = await fetch(testUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch ${testUrl}: ${response.status}`);
      }

      const html = await response.text();
      console.log(`Fetched ${html.length} characters from main Apple security page`);

      // Create scanner to test link extraction
      const scanner = new VulnerabilityScanner(this.env);

      // Use reflection to call private method (for testing purposes)
      const extractMethod = (scanner as any).extractIOSReleaseLinks;
      const iosReleases = extractMethod.call(scanner, html);

      const result = {
        message: 'Apple links parser test completed',
        test_url: testUrl,
        html_length: html.length,
        ios_releases_found: iosReleases.length,
        ios_releases: iosReleases.slice(0, 10), // Show first 10 releases
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(result, null, 2), { headers });

    } catch (error) {
      console.error('Apple links parser test failed:', error);

      const response = {
        message: 'Apple links parser test failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async processLatestIOS(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Processing latest iOS security release...');

      // Import required services
      const { AppleSecurityParser } = await import('../services/apple-security-parser');
      const { NVDClient } = await import('../services/nvd-client');

      // Process iOS 18.3 (the latest release we know has CVEs)
      const version = '18.3';
      const url = 'https://support.apple.com/en-us/122066';

      console.log(`Processing iOS ${version} from ${url}`);

      // Fetch the iOS security page
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
      }

      const html = await response.text();
      console.log(`Fetched ${html.length} characters from iOS security page`);

      // Parse vulnerabilities
      const parsedData = AppleSecurityParser.parseSecurityContent(html, version);
      console.log(`Found ${parsedData.vulnerabilities.length} vulnerabilities`);

      // Insert iOS release record
      const releaseId = await this.repository.insertIOSRelease({
        version: parsedData.version,
        release_date: parsedData.releaseDate,
        security_content_url: url,
      });

      console.log(`Inserted iOS release ${version} with ID ${releaseId}`);

      // Process vulnerabilities (limit to first 5 for testing)
      const nvdClient = new NVDClient(this.env);
      const processedVulns = [];
      const vulnsToProcess = parsedData.vulnerabilities.slice(0, 5);

      for (const vuln of vulnsToProcess) {
        try {
          console.log(`Processing ${vuln.cveId}...`);

          // Get CVSS data from NVD
          const cvssData = await nvdClient.getCVSSData(vuln.cveId);

          // Create vulnerability record
          const vulnerability = {
            id: vuln.cveId,
            cve_id: vuln.cveId,
            description: vuln.description,
            severity: cvssData?.severity || 'MEDIUM',
            cvss_score: cvssData?.score || null,
            cvss_vector: cvssData?.vector || null,
            ios_versions_affected: parsedData.version,
            discovered_date: parsedData.releaseDate,
          };

          // Insert into database
          await this.repository.insertVulnerability(vulnerability);

          // Link to release
          await this.repository.linkVulnerabilityToRelease(vuln.cveId, releaseId);

          processedVulns.push({
            cve_id: vuln.cveId,
            cvss_score: cvssData?.score,
            severity: cvssData?.severity,
          });

          console.log(`Processed ${vuln.cveId}: ${cvssData?.severity} (${cvssData?.score})`);

        } catch (error) {
          console.error(`Failed to process ${vuln.cveId}:`, error);
        }
      }

      const result = {
        message: 'Latest iOS processing completed',
        ios_version: version,
        release_id: releaseId,
        total_vulnerabilities: parsedData.vulnerabilities.length,
        processed_vulnerabilities: processedVulns.length,
        processed_details: processedVulns,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(result, null, 2), { headers });

    } catch (error) {
      console.error('Latest iOS processing failed:', error);

      const response = {
        message: 'Latest iOS processing failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async debugFullScan(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Debug: Running full vulnerability scan workflow...');

      // Import the VulnerabilityScanner
      const { VulnerabilityScanner } = await import('../services/vulnerability-scanner');

      const scanner = new VulnerabilityScanner(this.env);

      // Step 1: Get main page and extract links
      console.log('Step 1: Fetching main Apple security page...');
      const mainPageResponse = await fetch('https://support.apple.com/en-us/100100', {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!mainPageResponse.ok) {
        throw new Error(`Failed to fetch main page: ${mainPageResponse.status}`);
      }

      const mainPageHtml = await mainPageResponse.text();
      console.log(`Fetched ${mainPageHtml.length} characters from main page`);

      // Step 2: Extract iOS release links
      console.log('Step 2: Extracting iOS release links...');
      const extractMethod = (scanner as any).extractIOSReleaseLinks;
      const allReleases = extractMethod.call(scanner, mainPageHtml);
      console.log(`Found ${allReleases.length} total iOS releases`);

      // Step 3: Show version sorting
      const top10Releases = allReleases.slice(0, 10);
      console.log('Step 3: Top 10 releases by version:');

      const debugInfo = {
        message: 'Debug full scan workflow',
        step1_main_page_length: mainPageHtml.length,
        step2_total_releases_found: allReleases.length,
        step3_top_10_releases: top10Releases,
        step4_processing_results: [],
        timestamp: new Date().toISOString(),
      };

      // Step 4: Try to fetch details for top 3 releases
      console.log('Step 4: Testing release details fetching...');
      for (let i = 0; i < Math.min(3, allReleases.length); i++) {
        const release = allReleases[i];
        try {
          console.log(`Testing iOS ${release.version} from ${release.url}`);

          const releaseResponse = await fetch(release.url, {
            headers: {
              'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
          });

          const success = releaseResponse.ok;
          const contentLength = success ? (await releaseResponse.text()).length : 0;

          (debugInfo.step4_processing_results as any[]).push({
            version: release.version,
            url: release.url,
            fetch_success: success,
            status_code: releaseResponse.status,
            content_length: contentLength,
          });

          console.log(`iOS ${release.version}: ${success ? 'SUCCESS' : 'FAILED'} (${releaseResponse.status})`);

        } catch (error) {
          console.error(`Failed to test iOS ${release.version}:`, error);
          (debugInfo.step4_processing_results as any[]).push({
            version: release.version,
            url: release.url,
            fetch_success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      return new Response(JSON.stringify(debugInfo, null, 2), { headers });

    } catch (error) {
      console.error('Debug full scan failed:', error);

      const response = {
        message: 'Debug full scan failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async testLatestVersions(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Testing latest iOS versions for CVE content...');

      // Import the AppleSecurityParser
      const { AppleSecurityParser } = await import('../services/apple-security-parser');

      // Test the top 3 latest versions: iOS 26, iOS 18.7, iOS 18.6.2
      const versionsToTest = [
        { version: '26', url: 'https://support.apple.com/en-us/125108' },
        { version: '18.7', url: 'https://support.apple.com/en-us/125109' },
        { version: '18.6.2', url: 'https://support.apple.com/en-us/124925' },
      ];

      const results = [];

      for (const versionInfo of versionsToTest) {
        try {
          console.log(`Testing iOS ${versionInfo.version}...`);

          const response = await fetch(versionInfo.url, {
            headers: {
              'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
          });

          if (!response.ok) {
            throw new Error(`Failed to fetch: ${response.status}`);
          }

          const html = await response.text();
          const parsedData = AppleSecurityParser.parseSecurityContent(html, versionInfo.version);

          results.push({
            version: versionInfo.version,
            url: versionInfo.url,
            success: true,
            html_length: html.length,
            vulnerabilities_found: parsedData.vulnerabilities.length,
            release_date: parsedData.releaseDate,
            sample_cves: parsedData.vulnerabilities.slice(0, 3).map(v => v.cveId),
          });

          console.log(`iOS ${versionInfo.version}: ${parsedData.vulnerabilities.length} CVEs found`);

        } catch (error) {
          console.error(`Failed to test iOS ${versionInfo.version}:`, error);
          results.push({
            version: versionInfo.version,
            url: versionInfo.url,
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      const response = {
        message: 'Latest versions CVE testing completed',
        results: results,
        recommendation: this.getLatestVersionRecommendation(results),
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response, null, 2), { headers });

    } catch (error) {
      console.error('Latest versions test failed:', error);

      const response = {
        message: 'Latest versions test failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private getLatestVersionRecommendation(results: any[]): string {
    const validResults = results.filter(r => r.success && r.vulnerabilities_found > 0);
    if (validResults.length === 0) {
      return 'No versions with vulnerabilities found';
    }

    // Sort by semantic version parts (highest first)
    validResults.sort((a, b) => this.compareVersionsDesc(a.version, b.version));

    const latest = validResults[0];
    return `Recommended latest version to process: iOS ${latest.version} (${latest.vulnerabilities_found} CVEs)`;
  }

  private compareVersionsDesc(a: string, b: string): number {
    const aParts = (a || '').split('.').map(n => parseInt(n, 10) || 0);
    const bParts = (b || '').split('.').map(n => parseInt(n, 10) || 0);
    const len = Math.max(aParts.length, bParts.length);
    for (let i = 0; i < len; i++) {
      const av = aParts[i] || 0;
      const bv = bParts[i] || 0;
      if (av !== bv) return bv - av; // descending
    }
    return 0;
  }

  private async processAllLatestCVEs(headers: Record<string, string>): Promise<Response> {
    try {
      console.log('Processing ALL CVEs from the latest iOS version with CVSS scores...');

      // Import required services
      const { AppleSecurityParser } = await import('../services/apple-security-parser');
      const { NVDClient } = await import('../services/nvd-client');

      // Process iOS 26 (the actual latest version with most vulnerabilities)
      const version = '26';
      const url = 'https://support.apple.com/en-us/125108';

      console.log(`Processing ALL CVEs from iOS ${version}...`);

      // Fetch the iOS security page
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
      }

      const html = await response.text();
      console.log(`Fetched ${html.length} characters`);

      // Parse all vulnerabilities
      const parsedData = AppleSecurityParser.parseSecurityContent(html, version);
      console.log(`Found ${parsedData.vulnerabilities.length} total vulnerabilities`);

      // Clear existing data first to avoid conflicts
      await this.env.DB.prepare("DELETE FROM vulnerability_releases").run();
      await this.env.DB.prepare("DELETE FROM vulnerabilities WHERE ios_versions_affected = ?").bind(version).run();

      // Insert iOS release record
      const releaseId = await this.repository.insertIOSRelease({
        version: parsedData.version,
        release_date: parsedData.releaseDate,
        security_content_url: url,
      });

      console.log(`Inserted iOS release ${version} with ID ${releaseId}`);

      // Process ALL vulnerabilities with CVSS scores
      const nvdClient = new NVDClient(this.env);
      const processedVulns = [];
      const failedVulns = [];

      for (let i = 0; i < parsedData.vulnerabilities.length; i++) {
        const vuln = parsedData.vulnerabilities[i];
        try {
          console.log(`Processing ${i + 1}/${parsedData.vulnerabilities.length}: ${vuln.cveId}...`);

          // Get CVSS data from NVD
          const cvssData = await nvdClient.getCVSSData(vuln.cveId);

          // Create vulnerability record
          const vulnerability = {
            id: vuln.cveId,
            cve_id: vuln.cveId,
            description: vuln.description,
            severity: cvssData?.severity || 'MEDIUM',
            cvss_score: cvssData?.score || null,
            cvss_vector: cvssData?.vector || null,
            ios_versions_affected: parsedData.version,
            discovered_date: parsedData.releaseDate,
          };

          // Insert into database
          await this.repository.insertVulnerability(vulnerability);

          // Link to release
          await this.repository.linkVulnerabilityToRelease(vuln.cveId, releaseId);

          processedVulns.push({
            cve_id: vuln.cveId,
            cvss_score: cvssData?.score,
            severity: cvssData?.severity,
          });

          console.log(`✅ ${vuln.cveId}: ${cvssData?.severity} (${cvssData?.score})`);

        } catch (error) {
          console.error(`❌ Failed to process ${vuln.cveId}:`, error);
          failedVulns.push({
            cve_id: vuln.cveId,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      const result = {
        message: 'Latest iOS CVE processing completed',
        ios_version: version,
        release_id: releaseId,
        total_vulnerabilities: parsedData.vulnerabilities.length,
        successfully_processed: processedVulns.length,
        failed_processing: failedVulns.length,
        success_rate: `${Math.round((processedVulns.length / parsedData.vulnerabilities.length) * 100)}%`,
        severity_breakdown: this.getSeverityBreakdown(processedVulns),
        failed_cves: failedVulns.slice(0, 5), // Show first 5 failures
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(result, null, 2), { headers });

    } catch (error) {
      console.error('Latest CVE processing failed:', error);

      const response = {
        message: 'Latest CVE processing failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private getSeverityBreakdown(vulns: any[]): Record<string, number> {
    const breakdown: Record<string, number> = {};
    vulns.forEach(v => {
      const severity = v.severity || 'UNKNOWN';
      breakdown[severity] = (breakdown[severity] || 0) + 1;
    });
    return breakdown;
  }

  private async getDiscoveredIOSReleases(url: URL, headers: Record<string, string>): Promise<Response> {
    try {
      const majorFilter = url.searchParams.get('major');

      const response = await fetch(`${this.env.APPLE_SECURITY_BASE_URL}/en-us/100100`, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch Apple security releases: ${response.status}`);
      }

      const html = await response.text();
      const { VulnerabilityScanner } = await import('../services/vulnerability-scanner');
      const scanner = new VulnerabilityScanner(this.env);
      const extractMethod = (scanner as any).extractIOSReleaseLinks;
      const iosReleases = extractMethod.call(scanner, html) as Array<{ version: string; url: string }>;

      const filtered = majorFilter
        ? iosReleases.filter(r => r.version.startsWith(`${majorFilter}`))
        : iosReleases;

      return new Response(JSON.stringify({ count: filtered.length, releases: filtered }, null, 2), { headers });
    } catch (error) {
      console.error('Failed to discover iOS releases:', error);
      return new Response(JSON.stringify({ error: 'Failed to discover iOS releases' }), { status: 500, headers });
    }
  }

  private async manualReparse(request: Request, headers: Record<string, string>): Promise<Response> {
    try {
      // Simple authentication check
      const adminKey = request.headers.get('X-Admin-Key');
      if (adminKey !== 'manual-reparse-2024') {
        return new Response(
          JSON.stringify({ error: 'Unauthorized' }),
          { status: 401, headers }
        );
      }

      const body = await request.json() as { versions: string[], forceUpdate?: boolean };
      const { versions, forceUpdate = true } = body;

      if (!versions || !Array.isArray(versions) || versions.length === 0) {
        return new Response(
          JSON.stringify({ error: 'Invalid versions array' }),
          { status: 400, headers }
        );
      }

      console.log(`Manual reparse requested for versions: ${versions.join(', ')}`);

      // Import required services
      const { AppleSecurityParser } = await import('../services/apple-security-parser');
      const { NVDClient } = await import('../services/nvd-client');

      const nvdClient = new NVDClient(this.env);
      const results = [];

      for (const version of versions) {
        try {
          console.log(`\n=== Reparsing iOS ${version} ===`);

          // Find Apple security URL for this version
          const securityUrl = await this.findAppleSecurityUrl(version);
          if (!securityUrl) {
            console.error(`Could not find Apple security URL for iOS ${version}`);
            results.push({
              version,
              success: false,
              error: 'Could not find Apple security URL'
            });
            continue;
          }

          console.log(`Found security URL: ${securityUrl}`);

          // Fetch and parse Apple security content
          const response = await fetch(securityUrl, {
            headers: {
              'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
          });

          if (!response.ok) {
            throw new Error(`Failed to fetch ${securityUrl}: ${response.status}`);
          }

          const html = await response.text();
          const securityRelease = AppleSecurityParser.parseSecurityContent(html, version);

          if (!securityRelease || securityRelease.vulnerabilities.length === 0) {
            console.error(`No vulnerabilities found for iOS ${version}`);
            results.push({
              version,
              success: false,
              error: 'No vulnerabilities found'
            });
            continue;
          }

          console.log(`Found ${securityRelease.vulnerabilities.length} vulnerabilities for iOS ${version}`);

          // Check/insert iOS release record
          let releaseId: number;
          const existingRelease = await this.repository.getIOSReleaseByVersion(version);

          if (existingRelease) {
            releaseId = existingRelease.id!;
            console.log(`Using existing iOS release record ID: ${releaseId}`);
          } else {
            releaseId = await this.repository.insertIOSRelease({
              version: version,
              release_date: securityRelease.releaseDate,
              security_content_url: securityUrl,
            });
            console.log(`Created new iOS release record ID: ${releaseId}`);
          }

          // Process each vulnerability
          let updated = 0;
          let created = 0;
          const processedCves = [];

          for (const vuln of securityRelease.vulnerabilities) {
            try {
              const existingVuln = await this.repository.getVulnerabilityByCveId(vuln.cveId);

              let cvssData = null;
              let description = vuln.description;

              // Only fetch NVD data for new vulnerabilities or if forcing update
              if (!existingVuln || forceUpdate) {
                try {
                  cvssData = await nvdClient.getCVSSData(vuln.cveId);
                  const nvdDescription = await nvdClient.getCVEDescription(vuln.cveId);
                  description = nvdDescription || vuln.description;

                  // Rate limiting for NVD API
                  await new Promise(resolve => setTimeout(resolve, 100));

                } catch (nvdError) {
                  console.warn(`NVD lookup failed for ${vuln.cveId}:`, nvdError);
                  if (existingVuln) {
                    cvssData = {
                      score: existingVuln.cvss_score,
                      vector: existingVuln.cvss_vector,
                      severity: existingVuln.severity
                    };
                    description = existingVuln.description;
                  }
                }
              } else {
                // Use existing data
                cvssData = {
                  score: existingVuln.cvss_score,
                  vector: existingVuln.cvss_vector,
                  severity: existingVuln.severity
                };
                description = existingVuln.description;
              }

              const inferredSeverity = this.inferSeverityFromDescription(description);
              const vulnerability = {
                id: vuln.cveId,
                cve_id: vuln.cveId,
                description: description || 'Security vulnerability addressed in this update.',
                severity: cvssData?.severity || inferredSeverity || 'MEDIUM',
                cvss_score: (cvssData?.score !== undefined) ? cvssData.score : null,
                cvss_vector: cvssData?.vector || null,
                ios_versions_affected: version,
                discovered_date: securityRelease.releaseDate || new Date().toISOString().split('T')[0],
                apple_description: vuln.appleDescription,
                apple_available_for: vuln.availableFor,
                apple_impact: vuln.impact,
                apple_product: vuln.product,
              };

              await this.repository.insertVulnerability(vulnerability);
              await this.repository.linkVulnerabilityToRelease(vuln.cveId, releaseId);

              processedCves.push({
                cve_id: vuln.cveId,
                severity: vulnerability.severity,
                cvss_score: vulnerability.cvss_score,
                apple_product: vuln.product,
                apple_impact: vuln.impact
              });

              if (existingVuln) {
                updated++;
                console.log(`✓ Updated ${vuln.cveId} with Apple context`);
              } else {
                created++;
                console.log(`✓ Created ${vuln.cveId}`);
              }

            } catch (error) {
              console.error(`Failed to process ${vuln.cveId}:`, error);
            }
          }

          console.log(`iOS ${version} complete: ${created} created, ${updated} updated`);

          results.push({
            version,
            success: true,
            created,
            updated,
            total_vulnerabilities: securityRelease.vulnerabilities.length,
            sample_cves: processedCves.slice(0, 5)
          });

          // Rate limiting: wait 2 seconds between versions
          if (versions.indexOf(version) < versions.length - 1) {
            console.log('Waiting 2 seconds before next version...');
            await new Promise(resolve => setTimeout(resolve, 2000));
          }

        } catch (error) {
          console.error(`Failed to reparse iOS ${version}:`, error);
          results.push({
            version,
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      const response = {
        message: 'Manual reparse completed',
        requested_versions: versions,
        force_update: forceUpdate,
        results,
        summary: {
          total_versions: versions.length,
          successful: results.filter(r => r.success).length,
          failed: results.filter(r => !r.success).length,
        },
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response, null, 2), { headers });

    } catch (error) {
      console.error('Manual reparse failed:', error);

      const response = {
        message: 'Manual reparse failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async findAppleSecurityUrl(version: string): Promise<string | null> {
    try {
      // First check if we have this version in our database.
      // Validate the cached URL actually references the exact version to avoid stale/mis-cached mismatches (e.g., 18.1 vs 18.1.1)
      const existingRelease = await this.repository.getIOSReleaseByVersion(version);
      if (existingRelease && existingRelease.security_content_url) {
        try {
          const testResp = await fetch(existingRelease.security_content_url, {
            headers: {
              'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
          });
          if (testResp.ok) {
            const body = await testResp.text();
            const exact = new RegExp(`iOS\\s+${this.escapeRegex(version)}(?![\\d.])`, 'i');
            if (exact.test(body)) {
              console.log(`Validated cached URL for iOS ${version}: ${existingRelease.security_content_url}`);
              return existingRelease.security_content_url;
            }
            console.warn(`Cached URL did not validate for iOS ${version}, will rediscover: ${existingRelease.security_content_url}`);
          } else {
            console.warn(`Cached URL fetch failed (${testResp.status}) for iOS ${version}, will rediscover`);
          }
        } catch (e) {
          console.warn(`Cached URL validation error for iOS ${version}, will rediscover`, e);
        }
      }

      // Fetch Apple's main security releases page to discover URLs dynamically
      const response = await fetch(`${this.env.APPLE_SECURITY_BASE_URL}/en-us/100100`, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch Apple security releases: ${response.status}`);
      }

      const html = await response.text();

      // Look for exact version matches in iOS security release links
      // Pattern: <a href="/en-us/######">iOS X.Y[.Z] [and iPadOS X.Y[.Z]]</a>
      // Ensure we do NOT match longer versions when searching a shorter one (e.g., avoid 18.1.1 when searching 18.1)
      const exactVersionPattern = new RegExp(
        `<a[^>]+href="([^"]*\\/en-us\\/\\d+[^"]*)"[^>]*>([^<]*iOS\\s+${this.escapeRegex(version)}(?![\\d.])(?:\\s+and\\s+iPadOS\\s+\\d+(?:\\.\\d+)*)?[^<]*)`,
        'gi'
      );

      exactVersionPattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = exactVersionPattern.exec(html)) !== null) {
        // Validate that the visible text's extracted iOS version exactly equals the requested version
        const linkText = match[2] || '';
        const vMatch = linkText.match(/iOS\s+(\d+(?:\.\d+)*)/i);
        if (vMatch && vMatch[1] === version) {
          const relativeUrl = match[1];
          const url = relativeUrl.startsWith('http') ? relativeUrl : `${this.env.APPLE_SECURITY_BASE_URL}${relativeUrl}`;
          console.log(`Found exact match for iOS ${version}: ${linkText} -> ${url}`);

          // Cache this URL in database for future use
          try {
            await this.repository.insertIOSRelease({
              version: version,
              release_date: new Date().toISOString().split('T')[0], // Will be updated when parsed
              security_content_url: url,
            });
          } catch (error) {
            // Ignore duplicate insertion errors
            console.log(`iOS release ${version} already exists in database`);
          }

          return url;
        }
      }

      // If exact match not found, try broader patterns (but be more careful)
      const broaderPatterns = [
        // Look for iOS version with strict non-digit/non-dot boundary to avoid partial matches (e.g., 18.1.1)
        new RegExp(`<a[^>]+href="([^"]*\\/en-us\\/\\d+[^"]*)"[^>]*>([^<]*iOS\\s+${this.escapeRegex(version)}(?![\\d.])(?:\\s+and\\s+iPadOS\\s+\\d+(?:\\.\\d+)*)?[^<]*)`, 'gi'),
      ];

      for (const pattern of broaderPatterns) {
        pattern.lastIndex = 0; // Reset regex
        let patternMatch: RegExpExecArray | null;
        while ((patternMatch = pattern.exec(html)) !== null) {
          // Verify this is actually the right version
          const matchText = patternMatch[2] || '';
          const vMatch2 = matchText.match(/iOS\s+(\d+(?:\.\d+)*)/i);
          if (!vMatch2 || vMatch2[1] !== version) {
            continue;
          }

          const relativeUrl = patternMatch[1];
          const url = relativeUrl.startsWith('http') ? relativeUrl : `${this.env.APPLE_SECURITY_BASE_URL}${relativeUrl}`;

          console.log(`Found match for iOS ${version}: ${matchText} -> ${url}`);

          // Cache this URL in database
          try {
            await this.repository.insertIOSRelease({
              version: version,
              release_date: new Date().toISOString().split('T')[0],
              security_content_url: url,
            });
          } catch (error) {
            console.log(`iOS release ${version} already exists in database`);
          }

          return url;
        }
      }

      // Final fallback: reuse the extractor from VulnerabilityScanner for robust discovery
      try {
        const { VulnerabilityScanner } = await import('../services/vulnerability-scanner');
        const scanner = new VulnerabilityScanner(this.env);
        const extractMethod = (scanner as any).extractIOSReleaseLinks;
        const iosReleases = extractMethod.call(scanner, html) as Array<{ version: string; url: string }>;
        const found = iosReleases.find((r: any) => r.version === version);
        if (found) {
          const url = found.url.startsWith('http') ? found.url : `${this.env.APPLE_SECURITY_BASE_URL}${found.url}`;
          console.log(`Fallback extractor located iOS ${version}: ${url}`);
          try {
            await this.repository.insertIOSRelease({
              version: version,
              release_date: new Date().toISOString().split('T')[0],
              security_content_url: url,
            });
          } catch {}
          return url;
        }
      } catch (e) {
        console.warn('Extractor fallback failed:', e);
      }

      console.log(`No Apple security URL found for iOS ${version}`);
      return null;
    } catch (error) {
      console.error(`Error finding Apple security URL for iOS ${version}:`, error);
      return null;
    }
  }

  private escapeRegex(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  private inferSeverityFromDescription(description: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const lowerDesc = description.toLowerCase();

    if (lowerDesc.includes('remote code execution') ||
        lowerDesc.includes('arbitrary code execution') ||
        lowerDesc.includes('privilege escalation') ||
        lowerDesc.includes('kernel')) {
      return 'CRITICAL';
    }

    if (lowerDesc.includes('memory corruption') ||
        lowerDesc.includes('buffer overflow') ||
        lowerDesc.includes('use after free') ||
        lowerDesc.includes('sandbox escape')) {
      return 'HIGH';
    }

    if (lowerDesc.includes('information disclosure') ||
        lowerDesc.includes('denial of service') ||
        lowerDesc.includes('bypass')) {
      return 'MEDIUM';
    }

    return 'MEDIUM';
  }

  private async clearCachedUrls(request: Request, headers: Record<string, string>): Promise<Response> {
    try {
      // Simple authentication check
      const adminKey = request.headers.get('X-Admin-Key');
      if (adminKey !== 'manual-reparse-2024') {
        return new Response(
          JSON.stringify({ error: 'Unauthorized' }),
          { status: 401, headers }
        );
      }

      const body = await request.json() as { versions: string[] };
      const { versions } = body;

      if (!versions || !Array.isArray(versions) || versions.length === 0) {
        return new Response(
          JSON.stringify({ error: 'Invalid versions array' }),
          { status: 400, headers }
        );
      }

      console.log(`Clearing cached URLs for versions: ${versions.join(', ')}`);

      const results = [];
      for (const version of versions) {
        try {
          // 1) Delete relationships first to satisfy foreign key constraints
          // Delete links by release id
          await this.env.DB.prepare(
            "DELETE FROM vulnerability_releases WHERE ios_release_id IN (SELECT id FROM ios_releases WHERE version = ?)"
          ).bind(version).run();

          // Delete links by vulnerability id (any lingering ones)
          await this.env.DB.prepare(
            "DELETE FROM vulnerability_releases WHERE vulnerability_id IN (SELECT id FROM vulnerabilities WHERE ios_versions_affected = ?)"
          ).bind(version).run();

          // 2) Delete vulnerabilities for this version
          await this.env.DB.prepare(
            "DELETE FROM vulnerabilities WHERE ios_versions_affected = ?"
          ).bind(version).run();

          // 3) Delete the iOS release records for this version
          await this.env.DB.prepare(
            "DELETE FROM ios_releases WHERE version = ?"
          ).bind(version).run();

          results.push({
            version,
            success: true,
            message: 'Cached URL and data cleared'
          });

          console.log(`Cleared cached data for iOS ${version}`);
        } catch (error) {
          console.error(`Failed to clear cache for iOS ${version}:`, error);
          results.push({
            version,
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      const response = {
        message: 'Cache clearing completed',
        results,
        summary: {
          total_versions: versions.length,
          successful: results.filter(r => r.success).length,
          failed: results.filter(r => !r.success).length,
        },
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response, null, 2), { headers });

    } catch (error) {
      console.error('Cache clearing failed:', error);

      const response = {
        message: 'Cache clearing failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async getAvailableIOSVersions(headers: Record<string, string>): Promise<Response> {
    try {
      const versions = await this.repository.getAvailableIOSVersions();

      const response = {
        ios_versions: versions,
        count: versions.length,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), { headers });
    } catch (error) {
      console.error('Failed to get iOS versions:', error);

      const response = {
        error: 'Failed to get iOS versions',
        message: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }

  private async checkDatabaseIntegrity(headers: Record<string, string>): Promise<Response> {
    try {
      const integrity = await this.repository.checkDatabaseIntegrity();

      const response = {
        database_integrity: integrity,
        status: integrity.duplicate_cve_ids === 0 && integrity.duplicate_vulnerability_ids === 0 && integrity.duplicate_versions === 0 ? 'healthy' : 'issues_detected',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), { headers });
    } catch (error) {
      console.error('Failed to check database integrity:', error);

      const response = {
        error: 'Failed to check database integrity',
        message: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: 500,
        headers
      });
    }
  }
}
