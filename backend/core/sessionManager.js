'use strict';

/**
 * Session Manager — handles automated session persistence and token updates.
 * Features:
 *  - Cookie Jar (domain-based)
 *  - Automated Header/Parameter injection (for CSRF etc)
 *  - Request Pre-processing hooks
 */

const fs = require('fs');
const path = require('path');

class SessionManager {
    constructor() {
        this.cookies = new Map(); // domain -> { key: value }
        this.rules = [];          // { type: 'header'|'param', name: 'X-CSRF', source: 'last_resp_payload' }
        this.tokens = new Map();  // name -> value
    }

    // ── Cookie Jar ───────────────────────────────────────────────────
    updateCookies(host, setCookieHeader) {
        if (!setCookieHeader) return;
        const domainCookies = this.cookies.get(host) || {};
        const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
        
        cookies.forEach(c => {
            const [kv] = c.split(';');
            const [k, v] = kv.split('=');
            if (k && v) domainCookies[k.trim()] = v.trim();
        });
        this.cookies.set(host, domainCookies);
    }

    getCookieHeader(host) {
        const domainCookies = this.cookies.get(host);
        if (!domainCookies) return null;
        return Object.entries(domainCookies).map(([k, v]) => `${k}=${v}`).join('; ');
    }

    // ── Session Rules ───────────────────────────────────────────────
    addRule(rule) {
        this.rules.push(rule);
    }

    updateToken(name, value) {
        this.tokens.set(name, value);
    }

    /**
     * Pre-process a request before it's sent upstream.
     * Replaces placeholders or injects headers based on rules.
     */
    processRequest(req) {
        // 1. Inject Cookies from Jar
        const jarHeader = this.getCookieHeader(req.host);
        if (jarHeader) {
            // Merge with existing
            const existing = req.headers['cookie'] || '';
            req.headers['cookie'] = existing ? `${existing}; ${jarHeader}` : jarHeader;
        }

        // 2. Apply Custom Rules (e.g. Header injection)
        this.rules.forEach(rule => {
            if (rule.type === 'header' && this.tokens.has(rule.source)) {
                req.headers[rule.name] = this.tokens.get(rule.source);
            }
            if (rule.type === 'replace' && req.body) {
                // Example: replace CSRF placeholders in body
                req.body = req.body.replace(rule.placeholder, this.tokens.get(rule.source) || '');
            }
        });
    }

    // ── Persistence ──────────────────────────────────────────────────
    exportSnapshot() {
        return {
            cookies: Array.from(this.cookies.entries()),
            tokens: Array.from(this.tokens.entries())
        };
    }
}

module.exports = new SessionManager();
