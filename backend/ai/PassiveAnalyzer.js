'use strict';

/**
 * PassiveAnalyzer API
 * Analyzes requests/responses passively for common vulnerabilities.
 * Delegates to SpecializedDetectors for precise per-category findings.
 */

const { addFinding } = require('./reportGenerator');
const SpecializedDetectors = require('./SpecializedDetectors');

class PassiveAnalyzer {
    
    static detectMissingHeaders(ctx, findings) {
        const headers = Object.keys(ctx.resHeaders || {}).map(h => h.toLowerCase());
        const missing = [];
        if (!headers.includes('x-frame-options') && !headers.includes('content-security-policy')) {
            missing.push('X-Frame-Options');
        }
        if (!headers.includes('content-security-policy')) missing.push('Content-Security-Policy');
        if (!headers.includes('strict-transport-security') && ctx.url.startsWith('https')) missing.push('Strict-Transport-Security');

        if (missing.length > 0) {
            findings.push({
                type: 'Missing Security Headers',
                evidence: `Missing: ${missing.join(', ')}`,
                cvss_score: 5.3,
                severity: 'Medium',
                explanation: `The server failed to return the following critical security headers: ${missing.join(', ')}. This can leave the application vulnerable to clickjacking or other client-side attacks.`,
                impact: 'Vulnerability to Clickjacking, XSS, and MIME-sniffing attacks.',
                prevention: 'Apply modern security headers to all HTTP responses.',
            });
        }
    }

    static detectVersionDisclosure(ctx, findings) {
        const server = (ctx.resHeaders['server'] || '').toLowerCase();
        const poweredBy = (ctx.resHeaders['x-powered-by'] || '').toLowerCase();
        const combined = server + ' ' + poweredBy;
        
        let found = false;
        if (/(iis|apache|nginx|php|asp\.net)/i.test(combined)) found = true;

        if (found) {
            findings.push({
                type: 'Information Disclosure',
                evidence: `Server: ${ctx.resHeaders['server'] || 'N/A'}\nX-Powered-By: ${ctx.resHeaders['x-powered-by'] || 'N/A'}`,
                cvss_score: 5.3,
                severity: 'Medium',
                explanation: 'The server discloses precise architectural and version information via HTTP headers.',
                impact: 'Helps attackers target known vulnerabilities for these specific infrastructure versions.',
                prevention: 'Disable X-Powered-By, and set Server header to generic string.',
            });
        }
    }

    static detectCookieSecurity(ctx, findings) {
        let setCookies = ctx.resHeaders['set-cookie'];
        if (!setCookies) return;
        if (!Array.isArray(setCookies)) setCookies = [setCookies];
        
        let badCookies = [];
        for (let c of setCookies) {
            const cookieStr = c.toLowerCase();
            let missing = [];
            if (!cookieStr.includes('httponly')) missing.push('HttpOnly');
            if (ctx.url.startsWith('https') && !cookieStr.includes('secure')) missing.push('Secure');
            if (!cookieStr.includes('samesite')) missing.push('SameSite');
            
            if (missing.length > 0) {
                const cookieName = c.split('=')[0];
                badCookies.push(`${cookieName} (${missing.join(', ')})`);
            }
        }

        if (badCookies.length > 0) {
            findings.push({
                type: 'Insecure Cookie Attributes',
                evidence: badCookies.join('\n'),
                cvss_score: 5.3,
                severity: 'Medium',
                explanation: 'Cookies were set without necessary security flags (HttpOnly, Secure, SameSite) protecting them from compromise.',
                impact: 'Cookies can be read by JavaScript (via XSS) or sent unencrypted, risking session hijacking.',
                prevention: 'Always add Secure, HttpOnly, and SameSite=Lax (or Strict) to cookies.',
            });
        }
    }

    static detectProtocolIssues(ctx, findings) {
        if (ctx.url.startsWith('http://') && !ctx.url.includes('localhost') && !ctx.url.includes('127.0.0.1')) {
            findings.push({
                type: 'Cleartext Transmission (HTTP)',
                evidence: `Requested URL: ${ctx.url}`,
                cvss_score: 5.9,
                severity: 'Medium',
                explanation: 'Data is being transmitted over unencrypted HTTP rather than HTTPS.',
                impact: 'Attackers on the network path can easily intercept unencrypted communication.',
                prevention: 'Enforce strong TLS encryption (HTTPS) across the site.',
            });
        }
    }

    static detectStackTrace(ctx, findings) {
        // Delegated to SpecializedDetectors — no-op here to prevent duplicate types
    }

    static detectDebugMode(ctx, findings) {
        if (!ctx.resBody) return;
        if (ctx.url.toLowerCase().includes('debug') || /(verbose|debug info|phpinfo)/i.test(ctx.resBody.substring(0, 5000))) {
             findings.push({
                 type: 'Information Disclosure (Debug Mode)',
                 evidence: 'Debug markers or verbose logging discovered indicating debug mode is active.',
                 cvss_score: 5.3,
                 severity: 'Medium',
                 explanation: 'An endpoint or page appears to have verbose debugging enabled natively.',
                 impact: 'Reveals environmental details and configuration flaws.',
                 prevention: 'Ensure development/debug flags are strictly false in generation/production code.',
             });
        }
    }

    static detectInternalIPLeak(ctx, findings) {
        if (!ctx.resBody) return;
        // Regex for internal IPs
        const ipRegex = /\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b/g;
        const matches = (ctx.resBody.match(ipRegex) || []);
        
        let uniqueIps = [...new Set(matches)];
        // Filter out localhost
        uniqueIps = uniqueIps.filter(ip => ip !== '127.0.0.1');

        if (uniqueIps.length > 0) {
            findings.push({
                 type: 'Information Disclosure (Internal IP Leak)',
                 evidence: `Found internal IPs: ${uniqueIps.join(', ')}`,
                 cvss_score: 5.3,
                 severity: 'Medium',
                 explanation: 'The application leaked internal IPv4 addresses into the response output.',
                 impact: 'Assists an attacker in drawing an internal network mapping.',
                 prevention: 'Ensure server-side logic never binds raw internal topology to output JSON/HTML buffers.',
             });
        }
    }

    static analyze(ctx) {
        try {
            const findings = [];
            
            // ── Primary Passive Detectors ──
            this.detectMissingHeaders(ctx, findings);
            this.detectVersionDisclosure(ctx, findings);
            this.detectCookieSecurity(ctx, findings);
            this.detectProtocolIssues(ctx, findings);
            this.detectDebugMode(ctx, findings);
            this.detectInternalIPLeak(ctx, findings);

            // ── Save Passive Findings ──
            findings.forEach(f => addFinding({ ...ctx, ...f }));

            // ── Specialized Detectors (strict per-category, dedup-guarded) ──
            SpecializedDetectors.runAll({
                url: ctx.url,
                method: ctx.method,
                status: ctx.status,
                resHeaders: ctx.resHeaders || {},
                resBody: ctx.resBody || '',
                baseBody: '',
                payload: '',
            });
        } catch (e) {
            console.error('[PassiveAnalyzer] Error analyzing response:', e);
        }
    }
}

module.exports = PassiveAnalyzer;
