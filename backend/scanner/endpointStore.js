'use strict';
const { randomUUID } = require('crypto');

class EndpointStore {
    constructor() {
        this.endpoints = new Map(); // id -> { id, url, method, params, headers, tested }
    }

    clear() {
        this.endpoints.clear();
    }

    reset() {
        this.clear();
    }

    normalizeParams(paramsObj = {}) {
        const normalized = {};
        Object.keys(paramsObj).sort().forEach((key) => {
            const value = paramsObj[key];
            normalized[key] = value === undefined || value === null ? '' : String(value);
        });
        return normalized;
    }

    makeSignature(method, pathUrl, params) {
        const keys = Object.keys(params).sort();
        const pairs = keys.map((key) => `${key}=${params[key]}`);
        return `${method}:${pathUrl}:${pairs.join(',')}`;
    }

    add(url, method, paramsObj = {}, headers = {}) {
        try {
            const urlObj = new URL(url);
            const pathUrl = `${urlObj.origin}${urlObj.pathname}`;
            const queryParams = Object.fromEntries(urlObj.searchParams);
            const allParams = { ...queryParams, ...paramsObj };
            const normalizedParams = this.normalizeParams(allParams);
            const signature = this.makeSignature(method.toUpperCase(), pathUrl, normalizedParams);

            // Max 5 unique parameter variations per base URL path to prevent cart/form flooding
            const MAX_PER_URL = 5;
            let countForPath = 0;
            
            for (const endpoint of this.endpoints.values()) {
                const epUrl = new URL(endpoint.url);
                const epPathUrl = `${epUrl.origin}${epUrl.pathname}`;
                const existingSig = this.makeSignature(endpoint.method, epPathUrl, this.normalizeParams(endpoint.params));
                if (existingSig === signature) return false;
                if (epPathUrl === pathUrl && endpoint.method === method.toUpperCase()) {
                    countForPath++;
                }
            }

            // Skip if we already have enough variations for this path
            if (countForPath >= MAX_PER_URL) return false;

            const id = randomUUID();
            this.endpoints.set(id, {
                id,
                url,
                method: method.toUpperCase(),
                params: normalizedParams,
                headers: { ...headers },
                tested: false,
            });
            return true;
        } catch (e) {
            return false;
        }
    }

    getUntested() {
        for (const endpoint of this.endpoints.values()) {
            if (!endpoint.tested) {
                return endpoint;
            }
        }
        return null;
    }

    getNextUntested() {
        for (const endpoint of this.endpoints.values()) {
            if (!endpoint.tested) {
                endpoint.tested = true;
                return endpoint;
            }
        }
        return null;
    }

    markTested(id) {
        const endpoint = this.endpoints.get(id);
        if (endpoint) endpoint.tested = true;
    }

    getStats() {
        let total = 0;
        let tested = 0;
        for (const endpoint of this.endpoints.values()) {
            total += 1;
            if (endpoint.tested) tested += 1;
        }
        return {
            total,
            tested,
            untested: total - tested,
        };
    }
}

module.exports = new EndpointStore();
