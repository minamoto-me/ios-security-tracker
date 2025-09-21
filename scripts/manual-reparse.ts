import { Env, AppleSecurityRelease } from '../src/types';
import { VulnerabilityRepository } from '../src/database/repository';
import { AppleSecurityParser } from '../src/services/apple-security-parser';
import { NVDClient } from '../src/services/nvd-client';

/**
 * Manual script to re-parse specific iOS versions with Apple context
 * This bypasses existing data checks to force updates
 */
export class ManualReparser {
  private repository: VulnerabilityRepository;
  private nvdClient: NVDClient;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.repository = new VulnerabilityRepository(env);
    this.nvdClient = new NVDClient(env);
  }

  async reparseIOSVersions(versions: string[], forceUpdate: boolean = true): Promise<void> {
    console.log(`Starting manual reparse for iOS versions: ${versions.join(', ')}`);

    for (const version of versions) {
      try {
        await this.reparseIOSVersion(version, forceUpdate);

        // Rate limiting: wait 2 seconds between versions
        console.log('Waiting 2 seconds before next version...');
        await new Promise(resolve => setTimeout(resolve, 2000));

      } catch (error) {
        console.error(`Failed to reparse iOS ${version}:`, error);
      }
    }
  }

  private async reparseIOSVersion(version: string, forceUpdate: boolean): Promise<void> {
    console.log(`\n=== Reparsing iOS ${version} ===`);

    // Step 1: Find Apple security URL for this version
    const securityUrl = await this.findAppleSecurityUrl(version);
    if (!securityUrl) {
      console.error(`Could not find Apple security URL for iOS ${version}`);
      return;
    }

    console.log(`Found security URL: ${securityUrl}`);

    // Step 2: Fetch and parse Apple security content
    const securityRelease = await this.fetchAppleSecurityContent(securityUrl, version);
    if (!securityRelease || securityRelease.vulnerabilities.length === 0) {
      console.error(`No vulnerabilities found for iOS ${version}`);
      return;
    }

    console.log(`Found ${securityRelease.vulnerabilities.length} vulnerabilities for iOS ${version}`);

    // Step 3: Check/insert iOS release record
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

    // Step 4: Process each vulnerability
    let updated = 0;
    let created = 0;

    for (const vuln of securityRelease.vulnerabilities) {
      try {
        const existingVuln = await this.repository.getVulnerabilityByCveId(vuln.cveId);

        let cvssData = null;
        let description = vuln.description;

        // Only fetch NVD data for new vulnerabilities or if forcing update
        if (!existingVuln || forceUpdate) {
          try {
            cvssData = await this.nvdClient.getCVSSData(vuln.cveId);
            const nvdDescription = await this.nvdClient.getCVEDescription(vuln.cveId);
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
  }

  private async findAppleSecurityUrl(version: string): Promise<string | null> {
    try {
      // Fetch Apple's main security releases page
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

      // Look for links containing this iOS version
      const patterns = [
        new RegExp(`<a[^>]+href="([^"]*\\/en-us\\/HT\\d+[^"]*)"[^>]*>([^<]*iOS\\s+${this.escapeRegex(version)}[^<]*)`, 'gi'),
        new RegExp(`<a[^>]+href="([^"]*\\/en-us\\/\\d+[^"]*)"[^>]*>([^<]*iOS\\s+${this.escapeRegex(version)}[^<]*)`, 'gi'),
      ];

      for (const pattern of patterns) {
        const match = pattern.exec(html);
        if (match) {
          const relativeUrl = match[1];
          const url = relativeUrl.startsWith('http') ? relativeUrl : `${this.env.APPLE_SECURITY_BASE_URL}${relativeUrl}`;
          console.log(`Found security page for iOS ${version}: ${match[2]} -> ${url}`);
          return url;
        }
      }

      // If not found, try common URL patterns
      const commonUrls = [
        `${this.env.APPLE_SECURITY_BASE_URL}/en-us/HT213000`, // Common pattern
        `${this.env.APPLE_SECURITY_BASE_URL}/en-us/HT214000`, // Newer pattern
      ];

      for (const url of commonUrls) {
        try {
          const testResponse = await fetch(url, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36' }
          });
          if (testResponse.ok) {
            const testHtml = await testResponse.text();
            if (testHtml.includes(`iOS ${version}`) || testHtml.includes(`iOS${version}`)) {
              console.log(`Found iOS ${version} content at: ${url}`);
              return url;
            }
          }
        } catch (error) {
          // Continue to next URL
        }
      }

      return null;
    } catch (error) {
      console.error(`Error finding Apple security URL for iOS ${version}:`, error);
      return null;
    }
  }

  private async fetchAppleSecurityContent(url: string, version: string): Promise<AppleSecurityRelease | null> {
    try {
      console.log(`Fetching Apple security content from: ${url}`);

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
      const securityRelease = AppleSecurityParser.parseSecurityContent(html, version);

      if (!AppleSecurityParser.validateSecurityRelease(securityRelease)) {
        console.warn(`Invalid security release data for iOS ${version}`);
        return null;
      }

      return securityRelease;

    } catch (error) {
      console.error(`Failed to fetch Apple security content for iOS ${version}:`, error);
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
}

// Usage example:
// const env = { ... }; // Your environment
// const reparser = new ManualReparser(env);
// await reparser.reparseIOSVersions(['18.0', '18.1', '18.2', '18.3', '18.4', '18.5', '18.6'], true);