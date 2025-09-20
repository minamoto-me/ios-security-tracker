import { CVSSData, NVDVulnerability, Env } from '../types';

export class NVDClient {
  private baseUrl: string;
  private cache: KVNamespace;

  constructor(env: Env) {
    this.baseUrl = env.NVD_API_BASE_URL;
    this.cache = env.CACHE;
  }

  async getCVSSData(cveId: string): Promise<CVSSData | null> {
    try {
      // Check cache first
      const cacheKey = `nvd:cvss:${cveId}`;
      const cached = await this.cache.get(cacheKey, 'json');
      if (cached) {
        console.log(`Cache hit for CVE ${cveId}`);
        return cached as CVSSData;
      }

      console.log(`Fetching CVSS data for ${cveId} from NVD`);

      // Fetch from NVD API
      const url = `${this.baseUrl}/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'iOS-Security-Tracker/1.0',
          'Accept': 'application/json',
        },
      });

      if (!response.ok) {
        if (response.status === 404) {
          console.warn(`CVE ${cveId} not found in NVD`);
          return null;
        }
        if (response.status === 429) {
          console.warn(`Rate limited by NVD API for ${cveId}`);
          // Cache negative result for shorter time
          await this.cache.put(cacheKey, JSON.stringify(null), { expirationTtl: 300 });
          return null;
        }
        throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();

      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        console.warn(`No vulnerability data found for ${cveId}`);
        return null;
      }

      const vulnerability: NVDVulnerability = data.vulnerabilities[0];
      const cvssData = this.extractCVSSData(vulnerability);

      if (cvssData) {
        // Cache for 24 hours
        await this.cache.put(cacheKey, JSON.stringify(cvssData), { expirationTtl: 86400 });
        console.log(`CVSS data cached for ${cveId}:`, cvssData);
      }

      return cvssData;

    } catch (error) {
      console.error(`Failed to fetch CVSS data for ${cveId}:`, error);
      return null;
    }
  }

  private extractCVSSData(vulnerability: NVDVulnerability): CVSSData | null {
    const metrics = vulnerability.cve.metrics;
    if (!metrics) return null;

    // Prefer CVSS v3.1, fallback to v3.0
    let cvssMetric = metrics.cvssMetricV31?.[0];
    if (!cvssMetric) {
      cvssMetric = metrics.cvssMetricV30?.[0];
    }

    if (!cvssMetric) {
      console.warn(`No CVSS v3.x data found for ${vulnerability.cve.id}`);
      return null;
    }

    const cvssData = cvssMetric.cvssData;
    return {
      score: cvssData.baseScore,
      vector: cvssData.vectorString,
      severity: this.mapSeverity(cvssData.baseSeverity),
    };
  }

  private mapSeverity(nvdSeverity: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    switch (nvdSeverity.toUpperCase()) {
      case 'LOW':
        return 'LOW';
      case 'MEDIUM':
        return 'MEDIUM';
      case 'HIGH':
        return 'HIGH';
      case 'CRITICAL':
        return 'CRITICAL';
      default:
        console.warn(`Unknown severity: ${nvdSeverity}, defaulting to MEDIUM`);
        return 'MEDIUM';
    }
  }

  async getCVEDescription(cveId: string): Promise<string | null> {
    try {
      // Check cache first
      const cacheKey = `nvd:desc:${cveId}`;
      const cached = await this.cache.get(cacheKey, 'text');
      if (cached) {
        return cached;
      }

      console.log(`Fetching description for ${cveId} from NVD`);

      const url = `${this.baseUrl}/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'iOS-Security-Tracker/1.0',
          'Accept': 'application/json',
        },
      });

      if (!response.ok) {
        console.warn(`Failed to fetch description for ${cveId}: ${response.status}`);
        return null;
      }

      const data = await response.json();

      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        return null;
      }

      const vulnerability: NVDVulnerability = data.vulnerabilities[0];
      const descriptions = vulnerability.cve.descriptions;

      // Find English description
      const englishDesc = descriptions.find(desc => desc.lang === 'en');
      const description = englishDesc?.value || descriptions[0]?.value || null;

      if (description) {
        // Cache for 24 hours
        await this.cache.put(cacheKey, description, { expirationTtl: 86400 });
      }

      return description;

    } catch (error) {
      console.error(`Failed to fetch description for ${cveId}:`, error);
      return null;
    }
  }

  async batchGetCVSSData(cveIds: string[]): Promise<Map<string, CVSSData | null>> {
    const results = new Map<string, CVSSData | null>();

    // Process in batches to respect rate limits
    const batchSize = 5;
    const delayMs = 1000; // 1 second between batches

    for (let i = 0; i < cveIds.length; i += batchSize) {
      const batch = cveIds.slice(i, i + batchSize);

      console.log(`Processing CVE batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(cveIds.length / batchSize)}`);

      // Process batch in parallel
      const batchPromises = batch.map(async (cveId) => {
        const cvssData = await this.getCVSSData(cveId);
        results.set(cveId, cvssData);
      });

      await Promise.all(batchPromises);

      // Add delay between batches (except for the last batch)
      if (i + batchSize < cveIds.length) {
        await this.delay(delayMs);
      }
    }

    return results;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}