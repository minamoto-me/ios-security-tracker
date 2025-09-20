import { Env } from '../types';
import { VulnerabilityRepository } from '../database/repository';

export class ApiHandler {
  private repository: VulnerabilityRepository;

  constructor(env: Env) {
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
        if (path === '/api/logs') {
          return await this.getProcessingLogs(corsHeaders);
        }
        if (path === '/api/health') {
          return await this.getHealthCheck(corsHeaders);
        }
        if (path === '/' || path === '/api') {
          return await this.getApiInfo(corsHeaders);
        }
      }

      if (method === 'POST' && path === '/api/scan/trigger') {
        return await this.triggerManualScan(corsHeaders);
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

    const [vulnerabilities, total] = await Promise.all([
      this.repository.getAllVulnerabilities(limit, offset, severity, search),
      this.repository.getVulnerabilityCount(severity, search),
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
    // This would trigger a manual scan in a real implementation
    // For now, we'll return a placeholder response
    const response = {
      message: 'Manual scan request received',
      note: 'Scans are normally triggered weekly via cron schedule',
      scheduled_time: 'Every Monday at midnight UTC',
      timestamp: new Date().toISOString(),
    };

    return new Response(JSON.stringify(response), { headers });
  }
}