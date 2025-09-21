import { AppleSecurityRelease } from '../types';

export class AppleSecurityParser {
  private static readonly CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;
  private static readonly IOS_VERSION_REGEX = /iOS\s+(\d+(?:\.\d+)*(?:\.\d+)?)/gi;

  static parseSecurityContent(html: string, version: string): AppleSecurityRelease {
    const vulnerabilities: Array<{
      cveId: string;
      description: string;
      appleDescription?: string;
      availableFor?: string;
      impact?: string;
    }> = [];

    // Apple security pages use <p class="gb-paragraph"> elements containing CVE information
    // Parse HTML to find these elements (simplified approach without full DOM parser)
    const gbParagraphPattern = /<p[^>]*class="[^"]*gb-paragraph[^"]*"[^>]*>(.*?)<\/p>/gi;
    const cvePattern = /CVE-\d{4}-\d{4,7}/g;

    let match;
    const foundCves = new Set<string>();

    // Find all gb-paragraph elements
    while ((match = gbParagraphPattern.exec(html)) !== null) {
      const paragraphContent = match[1];

      // Look for CVE IDs in this paragraph
      const cveMatches = paragraphContent.match(cvePattern);
      if (cveMatches) {
        for (const cveId of cveMatches) {
          if (!foundCves.has(cveId)) {
            foundCves.add(cveId);

            // Extract description from the paragraph content
            const description = this.extractDescriptionFromParagraph(paragraphContent, cveId);
            if (description) {
              // Extract Apple-specific context for this CVE
              const appleContext = this.extractAppleContext(html, cveId);

              vulnerabilities.push({
                cveId,
                description: this.cleanDescription(description),
                appleDescription: appleContext.description,
                availableFor: appleContext.availableFor,
                impact: appleContext.impact,
                product: appleContext.product,
              });
              console.log(`Found CVE ${cveId}: ${description.substring(0, 100)}...`);
            }
          }
        }
      }
    }

    // Fallback: also check for CVEs in any paragraph elements if gb-paragraph didn't work
    if (vulnerabilities.length === 0) {
      const anyParagraphPattern = /<p[^>]*>(.*?)<\/p>/gi;
      while ((match = anyParagraphPattern.exec(html)) !== null) {
        const paragraphContent = match[1];
        const cveMatches = paragraphContent.match(cvePattern);
        if (cveMatches) {
          for (const cveId of cveMatches) {
            if (!foundCves.has(cveId)) {
              foundCves.add(cveId);
              const description = this.extractDescriptionFromParagraph(paragraphContent, cveId);
              if (description) {
                // Extract Apple-specific context for this CVE
                const appleContext = this.extractAppleContext(html, cveId);

                vulnerabilities.push({
                  cveId,
                  description: this.cleanDescription(description),
                  appleDescription: appleContext.description,
                  availableFor: appleContext.availableFor,
                  impact: appleContext.impact,
                  product: appleContext.product,
                });
                console.log(`Found CVE ${cveId} (fallback): ${description.substring(0, 100)}...`);
              }
            }
          }
        }
      }
    }

    // Extract release date from the page
    const releaseDate = this.extractReleaseDate(html, version);

    console.log(`Parsed ${vulnerabilities.length} vulnerabilities for iOS ${version}`);
    return {
      version,
      releaseDate,
      vulnerabilities,
    };
  }

  private static extractAppleContext(html: string, cveId: string): {
    description?: string;
    availableFor?: string;
    impact?: string;
    product?: string;
  } {
    const context = { description: undefined, availableFor: undefined, impact: undefined, product: undefined };

    // Find the CVE in the HTML
    const cveIndex = html.toLowerCase().indexOf(cveId.toLowerCase());
    if (cveIndex === -1) return context;

    // Extract a larger section around the CVE to look for Apple's structured information
    const searchRadius = 2000; // Look 2000 characters before and after
    const startIndex = Math.max(0, cveIndex - searchRadius);
    const endIndex = Math.min(html.length, cveIndex + searchRadius);
    const sectionHtml = html.substring(startIndex, endIndex);

    // Extract all elements (headers and paragraphs) in this section
    const allElementsPattern = /<(h[1-6]|p)[^>]*(?:class="[^"]*gb-(?:header|paragraph)[^"]*"[^>]*)?>([^<]*(?:<[^>]*>[^<]*)*?)<\/\1>/gi;
    let match;
    const elements: { type: string; content: string }[] = [];

    while ((match = allElementsPattern.exec(sectionHtml)) !== null) {
      const elementType = match[1];
      const elementContent = match[2].replace(/<[^>]*>/g, ' ').replace(/&[^;]+;/g, ' ').trim();
      if (elementContent) {
        elements.push({ type: elementType, content: elementContent });
      }
    }

    // Look for Apple product as a header before "Available for"
    for (let i = 0; i < elements.length; i++) {
      const element = elements[i];

      // Check if this is a header that could be an Apple product
      if (element.type.match(/^h[1-6]$/i) && element.content && element.content.length > 0) {
        // Look ahead to see if the next elements contain "Available for", "Impact", or "Description"
        const nextElements = elements.slice(i + 1, i + 4); // Check next 3 elements
        const hasAppleContext = nextElements.some(el =>
          el.content.match(/^(Available for|Impact|Description):/i)
        );

        if (hasAppleContext && !context.product) {
          // This header is likely the Apple product
          context.product = element.content.trim();
        }
      }

      // Process paragraphs for Apple-specific patterns
      if (element.type === 'p') {
        // Available for pattern
        if (element.content.match(/^Available for:/i)) {
          context.availableFor = element.content.replace(/^Available for:\s*/i, '').trim();
        }
        // Impact pattern
        else if (element.content.match(/^Impact:/i)) {
          context.impact = element.content.replace(/^Impact:\s*/i, '').trim();
        }
        // Description pattern (Apple's fix description)
        else if (element.content.match(/^Description:/i)) {
          context.description = element.content.replace(/^Description:\s*/i, '').trim();
        }
      }
    }

    return context;
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

  private static extractDescriptionFromParagraph(paragraphContent: string, cveId: string): string | null {
    // Remove HTML tags from paragraph content
    const cleanContent = paragraphContent.replace(/<[^>]*>/g, ' ').replace(/&[^;]+;/g, ' ');

    // Look for the CVE and extract surrounding text as description
    const cveIndex = cleanContent.indexOf(cveId);
    if (cveIndex === -1) return null;

    // Extract a reasonable amount of text around the CVE as description
    // Usually the vulnerability description follows the CVE ID
    const beforeCve = cleanContent.substring(Math.max(0, cveIndex - 50), cveIndex).trim();
    const afterCve = cleanContent.substring(cveIndex + cveId.length, cveIndex + cveId.length + 200).trim();

    // Combine and clean up the description
    let description = afterCve;

    // If there's no meaningful text after CVE, try before
    if (!description || description.length < 10) {
      description = beforeCve + ' ' + afterCve;
    }

    // Clean up and return
    return description.trim() || 'Security vulnerability addressed in this update.';
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
    return Boolean(
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