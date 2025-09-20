export interface Vulnerability {
  id: string;
  cve_id: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvss_score: number | null;
  cvss_vector: string | null;
  ios_versions_affected: string;
  discovered_date: string;
  created_at: string;
}

export interface IOSRelease {
  id: number;
  version: string;
  release_date: string;
  security_content_url: string;
  processed_at: string;
}

export interface ProcessingLog {
  id: number;
  run_date: string;
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED';
  vulnerabilities_found: number;
  vulnerabilities_new: number;
  vulnerabilities_updated: number;
  ios_releases_processed: number;
  execution_time_ms: number;
  errors: string | null;
}

export interface CVSSData {
  score: number;
  vector: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface NVDVulnerability {
  cve: {
    id: string;
    descriptions: Array<{
      lang: string;
      value: string;
    }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          baseScore: number;
          vectorString: string;
          baseSeverity: string;
        };
      }>;
      cvssMetricV30?: Array<{
        cvssData: {
          baseScore: number;
          vectorString: string;
          baseSeverity: string;
        };
      }>;
    };
  };
}

export interface AppleSecurityRelease {
  version: string;
  releaseDate: string;
  vulnerabilities: Array<{
    cveId: string;
    description: string;
  }>;
}

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ENVIRONMENT: string;
  NVD_API_BASE_URL: string;
  APPLE_SECURITY_BASE_URL: string;
  NVD_API_KEY?: string; // Optional NVD API key for higher rate limits
}