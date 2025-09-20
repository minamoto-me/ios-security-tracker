import { AppleSecurityRelease } from '../types';

export class AppleSecurityParser {
  private static readonly CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;
  private static readonly IOS_VERSION_REGEX = /iOS\s+(\d+(?:\.\d+)*(?:\.\d+)?)/gi;

  static parseSecurityContent(html: string, version: string): AppleSecurityRelease {
    const vulnerabilities: Array<{ cveId: string; description: string }> = [];

    // Extract CVE entries from the HTML
    const cveMatches = html.match(this.CVE_REGEX) || [];
    const uniqueCves = [...new Set(cveMatches)];

    // Parse each CVE entry with its description
    for (const cveId of uniqueCves) {
      const description = this.extractCVEDescription(html, cveId);
      if (description) {
        vulnerabilities.push({
          cveId,
          description: this.cleanDescription(description),
        });
      }
    }

    // Extract release date from the page
    const releaseDate = this.extractReleaseDate(html, version);

    return {
      version,
      releaseDate,
      vulnerabilities,
    };
  }

  private static extractCVEDescription(html: string, cveId: string): string | null {
    // Look for the CVE followed by its description
    const patterns = [
      // Pattern 1: CVE-XXXX-XXXX: Description
      new RegExp(`${this.escapeRegex(cveId)}\\s*:?\\s*([^\\n\\r]+)`, 'i'),
      // Pattern 2: CVE in a table or list format
      new RegExp(`${this.escapeRegex(cveId)}[\\s\\S]*?<[^>]*>([^<]+)`, 'i'),
      // Pattern 3: CVE followed by description in next element
      new RegExp(`${this.escapeRegex(cveId)}[\\s\\S]*?(?:<[^>]*>)*([^<\\n\\r]+)`, 'i'),
    ];

    for (const pattern of patterns) {
      const match = html.match(pattern);
      if (match && match[1] && match[1].trim().length > 10) {
        return match[1].trim();
      }
    }

    // Fallback: look for CVE in proximity to descriptive text
    const cveIndex = html.toLowerCase().indexOf(cveId.toLowerCase());
    if (cveIndex !== -1) {
      // Extract text around the CVE (500 characters after)
      const context = html.substring(cveIndex, cveIndex + 500);
      const cleanContext = this.stripHtmlTags(context);

      // Look for sentences that describe the vulnerability
      const sentences = cleanContext.split(/[.!?]/);
      for (const sentence of sentences) {
        if (sentence.length > 30 &&
            (sentence.includes('vulnerability') ||
             sentence.includes('issue') ||
             sentence.includes('flaw') ||
             sentence.includes('security'))) {
          return sentence.trim();
        }
      }
    }

    return null;
  }

  private static extractReleaseDate(html: string, version: string): string {
    // Look for common date patterns in Apple security pages
    const datePatterns = [
      // Pattern 1: "released on Month DD, YYYY"
      /released\s+on\s+([A-Za-z]+\s+\d{1,2},?\s+\d{4})/i,
      // Pattern 2: "Month DD, YYYY"
      /([A-Za-z]+\s+\d{1,2},?\s+\d{4})/,
      // Pattern 3: YYYY-MM-DD format
      /(\d{4}-\d{2}-\d{2})/,
      // Pattern 4: Published date
      /published:?\s*([A-Za-z]+\s+\d{1,2},?\s+\d{4})/i,
    ];

    for (const pattern of datePatterns) {
      const match = html.match(pattern);
      if (match && match[1]) {
        const dateStr = match[1].trim();
        const parsedDate = this.parseDate(dateStr);
        if (parsedDate) {
          return parsedDate;
        }
      }
    }

    // Fallback: use current date if no date found
    return new Date().toISOString().split('T')[0];
  }

  private static parseDate(dateStr: string): string | null {
    try {
      // Handle different date formats
      if (dateStr.match(/^\d{4}-\d{2}-\d{2}$/)) {
        return dateStr;
      }

      const date = new Date(dateStr);
      if (!isNaN(date.getTime())) {
        return date.toISOString().split('T')[0];
      }
    } catch (error) {
      console.warn('Failed to parse date:', dateStr, error);
    }
    return null;
  }

  private static cleanDescription(description: string): string {
    return this.stripHtmlTags(description)
      .replace(/\s+/g, ' ')
      .replace(/^[:\-\s]+/, '')
      .replace(/[:\-\s]+$/, '')
      .trim();
  }

  private static stripHtmlTags(html: string): string {
    return html.replace(/<[^>]*>/g, ' ').replace(/&[^;]+;/g, ' ');
  }

  private static escapeRegex(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  static validateSecurityRelease(release: AppleSecurityRelease): boolean {
    return (
      release.version &&
      release.releaseDate &&
      release.vulnerabilities.length > 0 &&
      release.vulnerabilities.every(vuln =>
        vuln.cveId.match(/^CVE-\d{4}-\d{4,7}$/) &&
        vuln.description &&
        vuln.description.length > 10
      )
    );
  }

  static extractIOSVersionsAffected(html: string, cveId: string): string {
    const cveIndex = html.toLowerCase().indexOf(cveId.toLowerCase());
    if (cveIndex === -1) return 'Unknown';

    // Look for iOS version information around the CVE
    const context = html.substring(Math.max(0, cveIndex - 200), cveIndex + 200);
    const versionMatches = context.match(this.IOS_VERSION_REGEX);

    if (versionMatches && versionMatches.length > 0) {
      const versions = [...new Set(versionMatches.map(match =>
        match.replace(/iOS\s+/i, '').trim()
      ))];
      return versions.join(', ');
    }

    return 'Unknown';
  }
}