'use strict';
// Avoid duplicates
class EndpointStore {
    constructor() {
        this.endpoints = new Map(); // key -> { url, method, params }
    }

    add(url, method, paramsObj = {}) {
        try {
            const urlObj = new URL(url);
            const pathUrl = `${urlObj.origin}${urlObj.pathname}`;
            
            // Collect query params + body params
            const queryParams = Object.fromEntries(urlObj.searchParams);
            const allParams = { ...queryParams, ...paramsObj };
            
            const paramKeys = Object.keys(allParams).sort().join(',');
            const sig = `${method}:${pathUrl}:${paramKeys}`;
            
            if (!this.endpoints.has(sig)) {
                this.endpoints.set(sig, { url, method, params: allParams, tested: false });
                return true; // Newly added
            }
        } catch (e) {}
        return false;
    }

    getUntested() {
        for (const [key, ep] of this.endpoints.entries()) {
            if (!ep.tested) {
                ep.tested = true;
                return ep;
            }
        }
        return null;
    }
    
    reset() {
        this.endpoints.clear();
    }
}

module.exports = new EndpointStore();
