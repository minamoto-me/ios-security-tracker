// iOS Security Vulnerability Tracker - Frontend JavaScript

class VulnerabilityTracker {
    constructor() {
        this.apiBase = 'https://ios-security-tracker.graceliu.workers.dev/api';
        this.currentPage = 0;
        this.pageSize = 20;
        this.currentFilters = {
            severity: '',
            search: '',
            ios_version: '',
            sort_by: 'discovered_date',
            sort_order: 'desc'
        };

        this.init();
    }

    async init() {
        this.setupEventListeners();
        await this.loadIOSVersions();
        await this.loadStats();
        await this.loadVulnerabilities();
        await this.loadSystemStatus();
    }

    setupEventListeners() {
        // Search functionality
        const searchBtn = document.getElementById('searchBtn');
        const searchInput = document.getElementById('searchInput');
        const severityFilter = document.getElementById('severityFilter');
        const iosVersionFilter = document.getElementById('iosVersionFilter');
        const sortByFilter = document.getElementById('sortByFilter');
        const sortOrderFilter = document.getElementById('sortOrderFilter');
        const clearFilters = document.getElementById('clearFilters');

        searchBtn?.addEventListener('click', () => this.performSearch());
        searchInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.performSearch();
        });
        severityFilter?.addEventListener('change', () => this.performSearch());
        iosVersionFilter?.addEventListener('change', () => this.performSearch());
        sortByFilter?.addEventListener('change', () => this.performSearch());
        sortOrderFilter?.addEventListener('change', () => this.performSearch());
        clearFilters?.addEventListener('click', () => this.clearFilters());

        // Pagination
        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');

        prevBtn?.addEventListener('click', () => this.previousPage());
        nextBtn?.addEventListener('click', () => this.nextPage());

        // Modal functionality
        const modal = document.getElementById('vulnerabilityModal');
        const closeBtn = modal?.querySelector('.close');

        closeBtn?.addEventListener('click', () => this.closeModal());
        window.addEventListener('click', (e) => {
            if (e.target === modal) this.closeModal();
        });
    }

    async loadIOSVersions() {
        try {
            const response = await fetch(`${this.apiBase}/ios-versions`);
            if (!response.ok) throw new Error('Failed to load iOS versions');

            const data = await response.json();
            this.populateIOSVersionFilter(data.ios_versions);
        } catch (error) {
            console.error('Error loading iOS versions:', error);
            // Fall back to hardcoded versions if API fails
            this.populateIOSVersionFilter(['18.7', '18.6', '18.5', '18.4', '18.3']);
        }
    }

    populateIOSVersionFilter(versions) {
        const iosVersionFilter = document.getElementById('iosVersionFilter');
        if (!iosVersionFilter) return;

        // Keep the "All iOS Versions" option
        iosVersionFilter.innerHTML = '<option value="">All iOS Versions</option>';

        // Add dynamic versions from database
        versions.forEach(version => {
            const option = document.createElement('option');
            option.value = version;
            option.textContent = `iOS ${version}`;
            iosVersionFilter.appendChild(option);
        });
    }

    async loadStats() {
        try {
            const response = await fetch(`${this.apiBase}/vulnerabilities/stats`);
            if (!response.ok) throw new Error('Failed to load stats');

            const data = await response.json();
            this.displayStats(data.stats);
        } catch (error) {
            console.error('Error loading stats:', error);
            this.displayStatsError();
        }
    }

    displayStats(stats) {
        const statsGrid = document.getElementById('statsGrid');
        if (!statsGrid) return;

        const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        const severityColors = {
            CRITICAL: 'critical',
            HIGH: 'high',
            MEDIUM: 'medium',
            LOW: 'low'
        };

        let html = `
            <div class="stat-card">
                <span class="stat-number">${stats.total}</span>
                <span class="stat-label">Total Vulnerabilities</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">${stats.recentCount}</span>
                <span class="stat-label">Last 30 Days</span>
            </div>
        `;

        severities.forEach(severity => {
            const count = stats.bySeverity[severity] || 0;
            html += `
                <div class="stat-card ${severityColors[severity]}">
                    <span class="stat-number">${count}</span>
                    <span class="stat-label">${severity}</span>
                </div>
            `;
        });

        statsGrid.innerHTML = html;
    }

    displayStatsError() {
        const statsGrid = document.getElementById('statsGrid');
        if (!statsGrid) return;

        statsGrid.innerHTML = `
            <div class="stat-card">
                <i class="fas fa-exclamation-triangle"></i>
                <span>Failed to load statistics</span>
            </div>
        `;
    }

    async loadVulnerabilities() {
        const listElement = document.getElementById('vulnerabilitiesList');
        if (!listElement) return;

        // Show loading state
        listElement.className = 'vulnerabilities-list loading';
        listElement.innerHTML = `
            <div class="loading-spinner">
                <i class="fas fa-spinner fa-spin"></i>
                <span>Loading vulnerabilities...</span>
            </div>
        `;

        try {
            const params = new URLSearchParams({
                limit: this.pageSize.toString(),
                offset: (this.currentPage * this.pageSize).toString()
            });

            if (this.currentFilters.severity) {
                params.append('severity', this.currentFilters.severity);
            }
            if (this.currentFilters.search) {
                params.append('search', this.currentFilters.search);
            }
            if (this.currentFilters.ios_version) {
                params.append('ios_version', this.currentFilters.ios_version);
            }
            if (this.currentFilters.sort_by) {
                params.append('sort_by', this.currentFilters.sort_by);
            }
            if (this.currentFilters.sort_order) {
                params.append('sort_order', this.currentFilters.sort_order);
            }

            const response = await fetch(`${this.apiBase}/vulnerabilities?${params}`);
            if (!response.ok) throw new Error('Failed to load vulnerabilities');

            const data = await response.json();
            this.displayVulnerabilities(data.vulnerabilities);
            this.updatePagination(data.pagination);
        } catch (error) {
            console.error('Error loading vulnerabilities:', error);
            this.displayVulnerabilitiesError();
        }
    }

    displayVulnerabilities(vulnerabilities) {
        const listElement = document.getElementById('vulnerabilitiesList');
        if (!listElement) return;

        listElement.className = 'vulnerabilities-list';

        if (vulnerabilities.length === 0) {
            listElement.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-search"></i>
                    <p>No vulnerabilities found matching your criteria.</p>
                </div>
            `;
            return;
        }

        const html = vulnerabilities.map(vuln => this.createVulnerabilityCard(vuln)).join('');
        listElement.innerHTML = html;

        // Add click listeners to vulnerability cards
        listElement.querySelectorAll('.vulnerability-card').forEach(card => {
            card.addEventListener('click', () => {
                const cveId = card.dataset.cveId;
                if (cveId) this.showVulnerabilityDetails(cveId);
            });
        });
    }

    createVulnerabilityCard(vuln) {
        const severityClass = `severity-${vuln.severity.toLowerCase()}`;
        const cvssScore = vuln.cvss_score ? vuln.cvss_score.toFixed(1) : 'N/A';
        const discoveredDate = new Date(vuln.discovered_date).toLocaleDateString();

        return `
            <div class="vulnerability-card" data-cve-id="${vuln.cve_id}">
                <div class="vulnerability-header">
                    <span class="cve-id">${vuln.cve_id}</span>
                    <span class="severity-badge ${severityClass}">${vuln.severity}</span>
                </div>
                <div class="vulnerability-description">
                    ${this.truncateText(vuln.description, 200)}
                </div>
                <div class="vulnerability-meta">
                    <div class="meta-item">
                        <i class="fas fa-calendar"></i>
                        <span>${discoveredDate}</span>
                    </div>
                    <div class="meta-item">
                        <i class="fas fa-mobile-alt"></i>
                        <span>iOS ${vuln.ios_versions_affected}</span>
                    </div>
                    <div class="meta-item">
                        <i class="fas fa-chart-line"></i>
                        <span class="cvss-score">CVSS: ${cvssScore}</span>
                    </div>
                </div>
            </div>
        `;
    }

    displayVulnerabilitiesError() {
        const listElement = document.getElementById('vulnerabilitiesList');
        if (!listElement) return;

        listElement.className = 'vulnerabilities-list';
        listElement.innerHTML = `
            <div class="text-center">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Failed to load vulnerabilities. Please try again later.</p>
                <button class="btn-primary" onclick="location.reload()">
                    <i class="fas fa-refresh"></i> Retry
                </button>
            </div>
        `;
    }

    updatePagination(pagination) {
        const paginationElement = document.getElementById('pagination');
        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');
        const pageInfo = document.getElementById('pageInfo');

        if (!paginationElement) return;

        if (pagination.total === 0) {
            paginationElement.style.display = 'none';
            return;
        }

        paginationElement.style.display = 'flex';

        const currentStart = pagination.offset + 1;
        const currentEnd = Math.min(pagination.offset + pagination.limit, pagination.total);

        if (pageInfo) {
            pageInfo.textContent = `Showing ${currentStart}-${currentEnd} of ${pagination.total}`;
        }

        if (prevBtn) {
            prevBtn.disabled = pagination.offset === 0;
        }

        if (nextBtn) {
            nextBtn.disabled = !pagination.has_more;
        }
    }

    async showVulnerabilityDetails(cveId) {
        const modal = document.getElementById('vulnerabilityModal');
        const detailsElement = document.getElementById('vulnerabilityDetails');

        if (!modal || !detailsElement) return;

        // Show modal with loading state
        modal.style.display = 'block';
        detailsElement.innerHTML = `
            <div class="loading-spinner">
                <i class="fas fa-spinner fa-spin"></i>
                <span>Loading vulnerability details...</span>
            </div>
        `;

        try {
            const response = await fetch(`${this.apiBase}/vulnerabilities/${encodeURIComponent(cveId)}`);
            if (!response.ok) throw new Error('Failed to load vulnerability details');

            const data = await response.json();
            this.displayVulnerabilityDetails(data.vulnerability);
        } catch (error) {
            console.error('Error loading vulnerability details:', error);
            detailsElement.innerHTML = `
                <div class="text-center">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Failed to load vulnerability details.</p>
                </div>
            `;
        }
    }

    displayVulnerabilityDetails(vuln) {
        const detailsElement = document.getElementById('vulnerabilityDetails');
        if (!detailsElement) return;

        const severityClass = `severity-${vuln.severity.toLowerCase()}`;
        const cvssScore = vuln.cvss_score ? vuln.cvss_score.toFixed(1) : 'Not Available';
        const discoveredDate = new Date(vuln.discovered_date).toLocaleDateString();
        const createdDate = new Date(vuln.created_at).toLocaleDateString();

        detailsElement.innerHTML = `
            <div class="vulnerability-details">
                <div class="vulnerability-header mb-2">
                    <h2>${vuln.cve_id}</h2>
                    <span class="severity-badge ${severityClass}">${vuln.severity}</span>
                </div>

                <div class="detail-section mb-2">
                    <h3>Description</h3>
                    <p>${vuln.description}</p>
                </div>

                ${this.generateAppleContextSection(vuln)}

                <div class="detail-grid">
                    <div class="detail-item">
                        <strong>CVSS Score:</strong>
                        <span class="cvss-score">${cvssScore}</span>
                    </div>
                    ${vuln.cvss_vector ? `
                        <div class="detail-item">
                            <strong>CVSS Vector:</strong>
                            <code>${vuln.cvss_vector}</code>
                        </div>
                    ` : ''}
                    <div class="detail-item">
                        <strong>iOS Versions Affected:</strong>
                        <span>${vuln.ios_versions_affected}</span>
                    </div>
                    <div class="detail-item">
                        <strong>Discovered Date:</strong>
                        <span>${discoveredDate}</span>
                    </div>
                    <div class="detail-item">
                        <strong>Last Updated:</strong>
                        <span>${createdDate}</span>
                    </div>
                </div>

                <div class="detail-actions">
                    <a href="https://nvd.nist.gov/vuln/detail/${vuln.cve_id}"
                       target="_blank" class="btn-primary">
                        <i class="fas fa-external-link-alt"></i> View on NVD
                    </a>
                </div>
            </div>
        `;
    }

    generateAppleContextSection(vuln) {
        // Only show Apple context if we have any Apple-specific information
        const hasAppleContext = vuln.apple_description || vuln.apple_available_for || vuln.apple_impact || vuln.apple_product;

        if (!hasAppleContext) {
            return '';
        }

        return `
            <div class="apple-context-section mb-2">
                <h3><i class="fab fa-apple"></i> Apple Security Information</h3>

                ${vuln.apple_product ? `
                    <div class="apple-detail-item mb-1">
                        <strong>Apple Product:</strong>
                        <p class="apple-product">${vuln.apple_product}</p>
                    </div>
                ` : ''}

                ${vuln.apple_impact ? `
                    <div class="apple-detail-item mb-1">
                        <strong>Impact:</strong>
                        <p class="apple-impact">${vuln.apple_impact}</p>
                    </div>
                ` : ''}

                ${vuln.apple_description ? `
                    <div class="apple-detail-item mb-1">
                        <strong>How Apple Fixed It:</strong>
                        <p class="apple-description">${vuln.apple_description}</p>
                    </div>
                ` : ''}

                ${vuln.apple_available_for ? `
                    <div class="apple-detail-item mb-1">
                        <strong>Available For:</strong>
                        <p class="apple-available-for">${vuln.apple_available_for}</p>
                    </div>
                ` : ''}
            </div>
        `;
    }

    closeModal() {
        const modal = document.getElementById('vulnerabilityModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async loadSystemStatus() {
        try {
            const response = await fetch(`${this.apiBase}/health`);
            const data = await response.json();
            this.displaySystemStatus(data);
        } catch (error) {
            console.error('Error loading system status:', error);
            this.displaySystemStatusError();
        }
    }

    displaySystemStatus(health) {
        const statusElement = document.getElementById('systemStatus');
        if (!statusElement) return;

        const isHealthy = health.status === 'healthy';
        const statusClass = isHealthy ? 'status-healthy' : 'status-unhealthy';
        const icon = isHealthy ? 'fas fa-check-circle' : 'fas fa-exclamation-circle';

        let html = `
            <div class="status-info ${statusClass}">
                <i class="${icon}"></i>
                <div>
                    <strong>System Status: ${health.status.toUpperCase()}</strong>
                    <div style="font-size: 0.9rem; margin-top: 0.25rem;">
                        Last updated: ${new Date(health.timestamp).toLocaleString()}
                    </div>
                </div>
            </div>
        `;

        if (health.database) {
            html += `
                <div style="margin-top: 1rem; font-size: 0.9rem;">
                    <strong>Database:</strong> Connected (${health.database.total_vulnerabilities} vulnerabilities)
                </div>
            `;
        }

        if (health.last_scan) {
            html += `
                <div style="margin-top: 0.5rem; font-size: 0.9rem;">
                    <strong>Last Scan:</strong> ${new Date(health.last_scan.date).toLocaleString()}
                    (Status: ${health.last_scan.status}, Found: ${health.last_scan.vulnerabilities_found})
                </div>
            `;
        }

        statusElement.innerHTML = html;
    }

    displaySystemStatusError() {
        const statusElement = document.getElementById('systemStatus');
        if (!statusElement) return;

        statusElement.innerHTML = `
            <div class="status-info status-unhealthy">
                <i class="fas fa-exclamation-circle"></i>
                <span>Unable to check system status</span>
            </div>
        `;
    }

    performSearch() {
        const searchInput = document.getElementById('searchInput');
        const severityFilter = document.getElementById('severityFilter');
        const iosVersionFilter = document.getElementById('iosVersionFilter');
        const sortByFilter = document.getElementById('sortByFilter');
        const sortOrderFilter = document.getElementById('sortOrderFilter');

        this.currentFilters.search = searchInput?.value?.trim() || '';
        this.currentFilters.severity = severityFilter?.value || '';
        this.currentFilters.ios_version = iosVersionFilter?.value || '';
        this.currentFilters.sort_by = sortByFilter?.value || 'discovered_date';
        this.currentFilters.sort_order = sortOrderFilter?.value || 'desc';
        this.currentPage = 0;

        this.loadVulnerabilities();
    }

    clearFilters() {
        const searchInput = document.getElementById('searchInput');
        const severityFilter = document.getElementById('severityFilter');
        const iosVersionFilter = document.getElementById('iosVersionFilter');
        const sortByFilter = document.getElementById('sortByFilter');
        const sortOrderFilter = document.getElementById('sortOrderFilter');

        if (searchInput) searchInput.value = '';
        if (severityFilter) severityFilter.value = '';
        if (iosVersionFilter) iosVersionFilter.value = '';
        if (sortByFilter) sortByFilter.value = 'discovered_date';
        if (sortOrderFilter) sortOrderFilter.value = 'desc';

        this.currentFilters = {
            search: '',
            severity: '',
            ios_version: '',
            sort_by: 'discovered_date',
            sort_order: 'desc'
        };
        this.currentPage = 0;

        this.loadVulnerabilities();
    }

    previousPage() {
        if (this.currentPage > 0) {
            this.currentPage--;
            this.loadVulnerabilities();
        }
    }

    nextPage() {
        this.currentPage++;
        this.loadVulnerabilities();
    }

    truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new VulnerabilityTracker();
});

// Add some global utility functions
window.refreshData = async function() {
    const tracker = new VulnerabilityTracker();
    await tracker.loadStats();
    await tracker.loadVulnerabilities();
    await tracker.loadSystemStatus();
};

// Auto-refresh every 5 minutes
setInterval(() => {
    window.refreshData();
}, 5 * 60 * 1000);