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
      product?: string;
    }> = [];

    console.log(`Parsing security content for ${version}...`);

    // Apple security pages have a specific structure:
    // <h3 class="gb-header">Product Name</h3>
    // <p class="gb-paragraph">Available for: ...</p>
    // <p class="gb-paragraph">Impact: ...</p>
    // <p class="gb-paragraph">Description: ...</p>
    // <p class="gb-paragraph">CVE-XXXX-XXXX: researcher</p>

    // Find all vulnerability sections by looking for h3 headers followed by CVE patterns
    const sectionPattern = /<h3[^>]*class="[^"]*gb-header[^"]*"[^>]*>([^<]+)<\/h3>([\s\S]*?)(?=<h3[^>]*class="[^"]*gb-header[^"]*"|$)/gi;

    let sectionMatch;
    while ((sectionMatch = sectionPattern.exec(html)) !== null) {
      const productName = sectionMatch[1].trim();
      const sectionContent = sectionMatch[2];

      console.log(`Found product section: ${productName}`);

      // Look for CVE IDs in this section
      const cvePattern = /CVE-\d{4}-\d{4,7}/g;
      const cveMatches = sectionContent.match(cvePattern);

      if (cveMatches) {
        console.log(`Found ${cveMatches.length} CVEs in ${productName} section`);

        // Extract section information
        const availableFor = this.extractFieldFromSection(sectionContent, 'Available for');
        const impact = this.extractFieldFromSection(sectionContent, 'Impact');
        const description = this.extractFieldFromSection(sectionContent, 'Description');

        // Create vulnerability entries for each CVE in this section
        for (const cveId of cveMatches) {
          vulnerabilities.push({
            cveId: cveId.trim(),
            description: description || `Security vulnerability in ${productName}`,
            appleDescription: description,
            availableFor: availableFor,
            impact: impact,
            product: productName,
          });
          console.log(`Added CVE ${cveId} for ${productName}`);
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
    const context: {
      description?: string;
      availableFor?: string;
      impact?: string;
      product?: string;
    } = {};

    // Find the CVE in the HTML
    const cveIndex = html.toLowerCase().indexOf(cveId.toLowerCase());
    if (cveIndex === -1) return context;

    // Extract a larger section around the CVE to look for Apple's structured information
    const searchRadius = 3000; // Increased search radius
    const startIndex = Math.max(0, cveIndex - searchRadius);
    const endIndex = Math.min(html.length, cveIndex + searchRadius);
    const sectionHtml = html.substring(startIndex, endIndex);

    // More flexible pattern to capture various HTML structures
    // Look for any headers and paragraphs, not just specific classes
    const headerPattern = /<(h[1-6])[^>]*>([^<]*(?:<[^>]*>[^<]*)*?)<\/\1>/gi;
    const paragraphPattern = /<p[^>]*>([^<]*(?:<[^>]*>[^<]*)*?)<\/p>/gi;

    const elements: { type: string; content: string; originalHtml: string }[] = [];

    // Extract headers
    let match;
    while ((match = headerPattern.exec(sectionHtml)) !== null) {
      const elementType = match[1];
      const elementContent = this.stripHtmlTags(match[2]).trim();
      if (elementContent && elementContent.length > 0) {
        elements.push({ type: elementType, content: elementContent, originalHtml: match[0] });
      }
    }

    // Extract paragraphs
    while ((match = paragraphPattern.exec(sectionHtml)) !== null) {
      const elementContent = this.stripHtmlTags(match[1]).trim();
      if (elementContent && elementContent.length > 0) {
        elements.push({ type: 'p', content: elementContent, originalHtml: match[0] });
      }
    }

    // Sort elements by their position in the HTML
    elements.sort((a, b) => {
      const aIndex = sectionHtml.indexOf(a.originalHtml);
      const bIndex = sectionHtml.indexOf(b.originalHtml);
      return aIndex - bIndex;
    });

    // Enhanced Apple context extraction with more flexible patterns
    for (let i = 0; i < elements.length; i++) {
      const element = elements[i];

      // Look for Apple products in headers
      if (element.type.match(/^h[1-6]$/i) && element.content.length > 0 && element.content.length < 100) {
        // Apple product patterns - look for common Apple component names
        const appleProductPatterns = [
          /^(Apple.*)/i,
          /^(Core.*)/i,
          /^(Foundation|Security|WebKit|Safari|Mail|Messages|FaceTime|Camera|Photos|Music)/i,
          /^(Audio|Video|Graphics|Network|Bluetooth|Wi-Fi)/i,
          /^(Kernel|System|Framework|Engine|Library)/i,
          /^(Face ID|Touch ID|Secure Enclave|Neural Engine)/i
        ];

        const isAppleProduct = appleProductPatterns.some(pattern => pattern.test(element.content));

        if (isAppleProduct || this.isLikelyAppleProduct(element, elements, i)) {
          if (!context.product) {
            context.product = element.content.trim();
          }
        }
      }

      // Enhanced pattern matching for Apple security fields
      if (element.type === 'p') {
        const content = element.content;

        // More flexible patterns for Apple's security information
        const patterns = [
          // Available for patterns
          { key: 'availableFor', patterns: [
            /^Available\s+for[:\s]+(.*)/i,
            /^Affects[:\s]+(.*)/i,
            /^Fixed\s+in[:\s]+(.*)/i
          ]},

          // Impact patterns
          { key: 'impact', patterns: [
            /^Impact[:\s]+(.*)/i,
            /^Security\s+Impact[:\s]+(.*)/i,
            /^Vulnerability[:\s]+(.*)/i
          ]},

          // Description patterns
          { key: 'description', patterns: [
            /^Description[:\s]+(.*)/i,
            /^Fix[:\s]+(.*)/i,
            /^Solution[:\s]+(.*)/i,
            /^Resolution[:\s]+(.*)/i
          ]}
        ];

        for (const patternGroup of patterns) {
          if (!context[patternGroup.key as keyof typeof context]) {
            for (const pattern of patternGroup.patterns) {
              const match = content.match(pattern);
              if (match && match[1] && match[1].trim().length > 5) {
                (context as any)[patternGroup.key] = match[1].trim();
                break;
              }
            }
          }
        }
      }
    }

    // Additional fallback: look for Apple context using text-based patterns in the entire section
    if (!context.availableFor || !context.impact || !context.description) {
      this.extractAppleContextFallback(sectionHtml, context);
    }

    // Debug logging to understand what we're extracting
    if (context.product || context.availableFor || context.impact || context.description) {
      console.log(`Apple context for ${cveId}:`, {
        product: context.product,
        availableFor: context.availableFor,
        impact: context.impact,
        description: context.description
      });
    } else {
      console.log(`No Apple context found for ${cveId}`);
    }

    return context;
  }

  private static extractFieldFromSection(sectionContent: string, fieldName: string): string | undefined {
    // Look for paragraphs that start with the field name
    const fieldPattern = new RegExp(`<p[^>]*class="[^"]*gb-paragraph[^"]*"[^>]*>\\s*${fieldName}:\\s*([^<]+)</p>`, 'i');
    const match = sectionContent.match(fieldPattern);

    if (match && match[1]) {
      return this.stripHtmlTags(match[1]).trim();
    }

    return undefined;
  }

  private static isLikelyAppleProduct(element: any, elements: any[], currentIndex: number): boolean {
    // Look ahead to see if the next elements contain Apple security patterns
    const nextElements = elements.slice(currentIndex + 1, currentIndex + 6); // Check next 5 elements

    const hasAppleSecurityContext = nextElements.some(el => {
      const content = el.content.toLowerCase();
      return content.includes('available for') ||
             content.includes('impact:') ||
             content.includes('description:') ||
             content.includes('vulnerability') ||
             content.includes('security');
    });

    // Check if the element looks like a component name (not too long, no common words)
    const content = element.content.toLowerCase();
    const isNotCommonText = !content.includes('the ') &&
                           !content.includes('this ') &&
                           !content.includes('vulnerability') &&
                           element.content.length < 50;

    return hasAppleSecurityContext && isNotCommonText;
  }

  private static extractAppleContextFallback(html: string, context: any): void {
    // Use more aggressive text-based extraction as fallback
    const cleanHtml = this.stripHtmlTags(html);

    // Look for patterns in the cleaned text
    const fallbackPatterns = [
      { key: 'availableFor', pattern: /Available\s+for[:\s]+([^\n\r.!?]*)/i },
      { key: 'impact', pattern: /Impact[:\s]+([^\n\r.!?]*)/i },
      { key: 'description', pattern: /Description[:\s]+([^\n\r.!?]*)/i }
    ];

    for (const { key, pattern } of fallbackPatterns) {
      if (!context[key]) {
        const match = cleanHtml.match(pattern);
        if (match && match[1] && match[1].trim().length > 5) {
          context[key] = match[1].trim();
        }
      }
    }
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