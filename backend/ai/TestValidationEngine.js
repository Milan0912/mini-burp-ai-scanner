'use strict';

/**
 * TestValidationEngine
 * ====================
 * Post-scan validator that checks if MiniBurp has discovered all 12
 * required vulnerabilities on the test target (testaspnet.vulnweb.com).
 *
 * Test Case → Finding Type Mapping (exact or fuzzy):
 *
 *  1. SQL Injection              → type contains "SQL Injection"
 *  2. Reflected XSS              → type contains "XSS"
 *  3. Stack Trace Disclosure     → type contains "Stack Trace"
 *  4. Cleartext Transmission     → type contains "Cleartext"
 *  5. IIS Version Disclosure     → type === "IIS Version Disclosure"
 *  6. ASP.NET Version Disclosure → type === "ASP.NET Version Disclosure"
 *  7. Debug Mode Enabled         → type contains "Debug Mode"
 *  8. Internal IP Disclosure     → type contains "Internal IP"
 *  9. Missing X-Frame-Options    → type contains "X-Frame-Options"
 * 10. Missing CSP                → type contains "CSP" or "Content-Security"
 * 11. Missing HSTS               → type contains "HSTS"
 * 12. Insecure Cookies           → type contains "Cookie"
 */

const reportGenerator = require('./reportGenerator');

// Ordered test cases for precise status display
const TEST_CASES = [
    { 
        id: 1,  
        label: 'SQL Injection',             
        match: f => /SQL Injection/i.test(f.type)
    },
    { 
        id: 2,  
        label: 'Reflected XSS',             
        match: f => /XSS/i.test(f.type)
    },
    { id: 3,  label: 'Stack Trace Disclosure',    match: f => /Stack Trace/i.test(f.type) },
    { id: 4,  label: 'Cleartext Transmission',    match: f => /Cleartext|HTTP/i.test(f.type) && !/Security/i.test(f.type) },
    { id: 5,  label: 'IIS Version Disclosure',    match: f => /IIS Version/i.test(f.type) },
    { id: 6,  label: 'ASP.NET Version Disclosure',match: f => /ASP\.NET Version/i.test(f.type) },
    { id: 7,  label: 'Debug Mode Enabled',        match: f => /Debug Mode/i.test(f.type) },
    { id: 8,  label: 'Internal IP Disclosure',    match: f => /Internal IP/i.test(f.type) },
    { id: 9,  label: 'Missing X-Frame-Options',   match: f => /X-Frame-Options/i.test(f.type) },
    { id: 10, label: 'Missing CSP',               match: f => /CSP|Content-Security/i.test(f.type) },
    { id: 11, label: 'Missing HSTS',              match: f => /HSTS/i.test(f.type) },
    { id: 12, label: 'Insecure Cookies',          match: f => /Cookie/i.test(f.type) },
];

class TestValidationEngine {
    constructor() {
        this.TEST_CASES = TEST_CASES;
        // Keep backward compat
        this.REQUIRED_VULNS = TEST_CASES.map(t => t.label);
    }

    /**
     * Run validation against all findings in the report store.
     * @param {string} url - target URL being scanned
     * @returns {Object|null} validation results or null if not the test target
     */
    validateTarget(url) {
        // Only validate against the known test target (or allow any target in non-strict mode)
        const isTestTarget = url && url.includes('testaspnet.vulnweb.com');
        // Still run validation for any target to show the UI scoreboard
        // but only report re-test for the known target

        const findings = reportGenerator.getFindings ? reportGenerator.getFindings() : [];

        const results = {
            target: url,
            total: TEST_CASES.length,
            passed: 0,
            failed: 0,
            details: [],
            missing: [],
            status: 'FAILED',
            timestamp: new Date().toISOString(),
        };

        for (const tc of TEST_CASES) {
            const found = findings.some(f => tc.match(f));
            const confidence = found
                ? Math.max(...findings.filter(f => tc.match(f)).map(f => f.confidence_score || 80))
                : 0;

            results.details.push({
                id: tc.id,
                label: tc.label,
                passed: found,
                confidence,
            });

            if (found) {
                results.passed++;
            } else {
                results.failed++;
                results.missing.push(tc.label);
            }
        }

        if (results.passed >= TEST_CASES.length) {
            results.status = 'PASSED';
        } else if (results.passed >= TEST_CASES.length * 0.7) {
            results.status = 'PARTIAL';
        }

        return results;
    }
}

module.exports = new TestValidationEngine();
