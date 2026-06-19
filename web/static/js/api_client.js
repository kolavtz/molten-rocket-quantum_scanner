/* Centralized API client helpers and envelope normalizer */
(function () {
    'use strict';

    const ApiClient = {
        normalizeApiEnvelope(payload) {
            if (!payload) return { success: false, data: null, message: null, status: null };
            if (typeof payload === 'object' && ('success' in payload || 'data' in payload || 'status' in payload)) {
                return payload;
            }
            if (payload && payload.status) {
                return {
                    success: String(payload.status).toLowerCase() === 'success' || String(payload.status).toLowerCase() === 'complete',
                    status: payload.status,
                    data: payload.data || null,
                    message: payload.message || null
                };
            }
            if (payload && payload.data) {
                return { success: true, data: payload.data, message: payload.message || null };
            }
            return { success: false, data: payload || null, message: payload && payload.message ? payload.message : null };
        },

        async fetchEnvelope(url, opts) {
            const resp = await fetch(url, opts);
            let raw = null;
            try { raw = await resp.json(); } catch (e) { /* ignore */ }
            if (!resp.ok) {
                // Try to return any useful structured error
                const normalized = ApiClient.normalizeApiEnvelope(raw);
                normalized.status = resp.status;
                if (!('success' in normalized)) normalized.success = false;
                return normalized;
            }
            return ApiClient.normalizeApiEnvelope(raw);
        }
    };

    window.ApiClient = ApiClient;
    window.normalizeApiEnvelope = ApiClient.normalizeApiEnvelope;
    window.fetchEnvelope = ApiClient.fetchEnvelope;
})();
/**
 * Universal API Client for QuantumShield Dashboards
 * Provides standardized fetching, caching, and error handling
 */

class APIClient {
    constructor(baseUrl = '/api', timeout = 30000) {
        this.baseUrl = baseUrl;
        this.timeout = timeout;
        this.cache = new Map();
        this.cacheTimeout = 60000; // 1 minute default
    }

    /**
     * Make an API request with standardized error handling
     */
    async fetch(endpoint, options = {}) {
        const {
            method = 'GET',
            body = null,
            useCache = true,
            cacheKey = null,
            headers = {}
        } = options;

        const url = `${this.baseUrl}${endpoint}`;
        const cacheKeyFinal = cacheKey || `${method}:${url}`;

        // Check cache for GET requests
        if (method === 'GET' && useCache && this.cache.has(cacheKeyFinal)) {
            const cached = this.cache.get(cacheKeyFinal);
            if (Date.now() - cached.timestamp < this.cacheTimeout) {
                return cached.data;
            } else {
                this.cache.delete(cacheKeyFinal);
            }
        }

        try {
            const fetchOptions = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers
                },
                timeout: this.timeout
            };

            if (body) {
                fetchOptions.body = JSON.stringify(body);
            }

            const response = await fetch(url, fetchOptions);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(
                    errorData.message || `HTTP ${response.status}: ${response.statusText}`
                );
            }

            const data = await response.json();

            // Cache successful GET responses
            if (method === 'GET' && useCache) {
                this.cache.set(cacheKeyFinal, {
                    data,
                    timestamp: Date.now()
                });
            }

            return data;
        } catch (error) {
            console.error(`API Error [${endpoint}]:`, error);
            throw error;
        }
    }

    /**
     * Build query string from parameters
     */
    buildQuery(params) {
        return Object.entries(params)
            .filter(([, value]) => value !== null && value !== undefined && value !== '')
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
            .join('&');
    }

    /**
     * Get home dashboard metrics
     */
    async getHomeMetrics() {
        return this.fetch('/home/metrics');
    }

    /**
     * Get paginated assets list
     */
    async getAssets(params = {}) {
        const query = this.buildQuery({
            page: params.page || 1,
            page_size: params.pageSize || 25,
            sort: params.sort || 'asset_name',
            order: params.order || 'asc',
            q: params.search || ''
        });

        return this.fetch(`/assets?${query}`);
    }

    /**
     * Get asset details
     */
    async getAsset(assetId) {
        return this.fetch(`/assets/${assetId}`);
    }

    /**
     * Get discovery items by tab
     */
    async getDiscovery(tab = 'domains', params = {}) {
        const query = this.buildQuery({
            tab,
            page: params.page || 1,
            page_size: params.pageSize || 25,
            sort: params.sort || 'detection_date',
            order: params.order || 'desc',
            q: params.search || ''
        });

        return this.fetch(`/discovery?${query}`);
    }

    /**
     * Get CBOM metrics
     */
    async getCBOMMetrics() {
        return this.fetch('/cbom/metrics');
    }

    /**
     * Get CBOM entries
     */
    async getCBOMEntries(params = {}) {
        const query = this.buildQuery({
            page: params.page || 1,
            page_size: params.pageSize || 25,
            sort: params.sort || 'key_length',
            order: params.order || 'desc'
        });

        return this.fetch(`/cbom/entries?${query}`);
    }

    /**
     * Get CBOM summary for a scan
     */
    async getCBOMSummary(scanId) {
        return this.fetch(`/cbom/summary?scan_id=${scanId}`);
    }

    /**
     * Get PQC posture metrics
     */
    async getPQCMetrics() {
        return this.fetch('/pqc-posture/metrics');
    }

    /**
     * Get PQC assets with scores
     */
    async getPQCAssets(params = {}) {
        const query = this.buildQuery({
            page: params.page || 1,
            page_size: params.pageSize || 25,
            sort: params.sort || 'pqc_score',
            order: params.order || 'desc'
        });

        return this.fetch(`/pqc-posture/assets?${query}`);
    }

    /**
     * Get cyber rating
     */
    async getCyberRating() {
        return this.fetch('/cyber-rating');
    }

    /**
     * Get cyber rating history
     */
    async getCyberRatingHistory(params = {}) {
        const query = this.buildQuery({
            page: params.page || 1,
            page_size: params.pageSize || 25
        });

        return this.fetch(`/cyber-rating/history?${query}`);
    }

    /**
     * Get scheduled reports
     */
    async getScheduledReports(params = {}) {
        const query = this.buildQuery({
            page: params.page || 1,
            page_size: params.pageSize || 25
        });

        return this.fetch(`/reports/scheduled?${query}`);
    }

    /**
     * Get on-demand reports
     */
    async getOnDemandReports(params = {}) {
        const query = this.buildQuery({
            page: params.page || 1,
            page_size: params.pageSize || 25,
            sort: params.sort || 'generated_at',
            order: params.order || 'desc'
        });

        return this.fetch(`/reports/ondemand?${query}`);
    }

    /**
     * Clear cache for all or specific endpoint
     */
    clearCache(pattern = null) {
        if (!pattern) {
            this.cache.clear();
            return;
        }

        for (const [key] of this.cache) {
            if (key.includes(pattern)) {
                this.cache.delete(key);
            }
        }
    }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = APIClient;
}

// Create global instance
const api = new APIClient();

if (typeof window !== 'undefined') {
    window.QuantumShieldApiClient = api;
}
