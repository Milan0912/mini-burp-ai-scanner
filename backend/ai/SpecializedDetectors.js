'use strict';

/**
 * SpecializedDetectors.js
 * ========================
 * Standalone detection modules for all 12 MiniBurp test cases.
 * These modules enrich PassiveAnalyzer with sharper, test-driven detection logic.
 * Results are emitted directly to reportGenerator.
 *
 * Detection coverage:
 *  1. Stack Trace Disclosure
 *  2. XSS Reflection verification
 *  3. Cookie Security (HttpOnly, Secure, SameSite per-cookie)
 *  4. IIS Version Disclosure (classified separately from generic)
 *  5. ASP.NET Version Disclosure (classified separately)
 *  6. Debug Mode Detection
 *  7. Internal IP Leak
 *  8. HSTS Missing (HTTPS only)
 *  9. X-Frame-Options Missing
 * 10. Content-Security-Policy Missing
 * 11. Cleartext HTTP
 */

const { addFinding } = require('./reportGenerator');

// ── Dedup guard ────────────────────────────────────────────────────────────
const _emitted = new Set();
function _emit(type, url, finding) {
    const key = `${type}::${url}`;
    if (_emitted.has(key)) return;
    _emitted.add(key);

    // Attach required fields
    try {
        const u = new URL(url.startsWith('http') ? url : `http://localhost${url}`);
        finding.endpoint = u.pathname;
        finding.host = u.host;
    } catch (_) {
        finding.endpoint = url;
        finding.host = url;
    }

    finding.url = url;
    finding.fullUrl = url;
    finding.confidence_score = finding.confidence_score || 95;
    finding.parameter = finding.parameter || 'Passive';
    finding.method = finding.method || 'GET';
    finding.raw_request = finding.raw_request || `${finding.method} ${url}`;
    finding.raw_response = finding.raw_response || '';

    addFinding(finding);
}

// ── 1. Stack Trace Disclosure ──────────────────────────────────────────────
const STACK_TRACE_REGEX = /Exception|Stack trace|at System\.|System\.Web\.|Unhandled exception|Microsoft\.NET|ASP\.NET Runtime|Compilation Error|Line \d+:/i;

function detectStackTrace(url, method, body, baseBody, status) {
    if (!body) return;
    const isError = status >= 400; // ASP.NET often shows details on 404/500
    if (STACK_TRACE_REGEX.test(body) && (isError || !STACK_TRACE_REGEX.test(baseBody || ''))) {
        _emit('Stack Trace Disclosure', url, {
            type: 'Stack Trace Disclosure',
            severity: 'Medium',
            cvss_score: 5.3,
            evidence: (() => {
                const m = body.match(STACK_TRACE_REGEX);
                return `Found keyword: "${m ? m[0] : 'Exception'}" in response body.`;
            })(),
            explanation: 'The application exposes internal call stack traces on errors, revealing file paths, class names, and framework versions to unauthenticated users.',
            impact: 'Assists targeted exploitation using framework-specific CVEs and discloses application internals.',
            prevention: 'Configure custom error pages. In ASP.NET, set <customErrors mode="On"> and disable debug compilation.',
            method,
        });
    }
}

// ── 2. XSS Reflection Verification ────────────────────────────────────────
const XSS_MARKERS = ['<script>', 'onerror=', '<svg', 'javascript:', 'alert(', 'prompt('];

function detectXSSReflection(url, method, payload, responseBody, baseBody) {
    if (!payload || !responseBody) return;
    const bodyLower = responseBody.toLowerCase();
    const payloadLower = payload.toLowerCase();
    const baseLower = (baseBody || '').toLowerCase();

    // STRICT: Only flag if payload contains common XSS injection markers and is reflected
    const hasMarker = XSS_MARKERS.some(m => payloadLower.includes(m));
    const isReflected = bodyLower.includes(payloadLower) && !baseLower.includes(payloadLower);

    if (hasMarker && isReflected) {
        _emit('Reflected XSS', url, {
            type: 'Reflected XSS',
            severity: 'High',
            cvss_score: 7.4,
            evidence: `Injection of "${payload.slice(0, 30)}..." reflected in response.`,
            explanation: 'User-supplied script markers were returned unescaped in the response body.',
            impact: 'Complete browser session compromise via client-side script execution.',
            prevention: 'Context-aware HTML encoding and strict CSP implementation.',
            method,
            payload,
            confidence_score: 95
        });
    }
}

// ── 3. Cookie Security ─────────────────────────────────────────────────────
function detectInsecureCookies(url, method, resHeaders) {
    if (!resHeaders) return;

    let setCookies = resHeaders['set-cookie'] || resHeaders['Set-Cookie'];
    if (!setCookies) return;
    if (!Array.isArray(setCookies)) setCookies = [setCookies];

    const badCookies = [];
    for (const cookie of setCookies) {
        const lower = cookie.toLowerCase();
        const missing = [];
        if (!lower.includes('httponly')) missing.push('HttpOnly');
        if (!lower.includes('samesite')) missing.push('SameSite');
        // Only flag Secure on HTTPS targets
        if (url.startsWith('https') && !lower.includes('; secure')) missing.push('Secure');

        if (missing.length > 0) {
            const name = cookie.split('=')[0].trim();
            badCookies.push(`${name} (missing: ${missing.join(', ')})`);
        }
    }

    if (badCookies.length > 0) {
        _emit('Insecure Cookies', url, {
            type: 'Insecure Cookies',
            severity: 'Medium',
            cvss_score: 5.3,
            evidence: badCookies.join('\n'),
            explanation: 'Session cookies lack security attributes that protect them against theft and misuse.',
            impact: 'Session fixation, XSS-based cookie theft, and cross-site request forgery.',
            prevention: 'Set HttpOnly, Secure (on HTTPS), and SameSite=Lax on all Set-Cookie responses.',
            method,
        });
    }
}

// ── 4. IIS Version Disclosure ──────────────────────────────────────────────
function detectIISVersion(url, method, resHeaders) {
    if (!resHeaders) return;
    const server = resHeaders['server'] || resHeaders['Server'] || '';
    const match = server.match(/Microsoft-IIS\/([\d.]+)/i);
    if (match) {
        _emit('IIS Version Disclosure', url, {
            type: 'IIS Version Disclosure',
            severity: 'Low',
            cvss_score: 5.3,
            evidence: `Server: ${server}`,
            explanation: `The server discloses its exact IIS version (${match[1]}) in the "Server" HTTP response header.`,
            impact: 'Attackers can target publicly known CVEs specific to the disclosed IIS version.',
            prevention: 'Set the Server header to a generic value or suppress it entirely via IIS Manager → HTTP Response Headers.',
            method,
        });
    }
}

// ── 5. ASP.NET Version Disclosure ─────────────────────────────────────────
function detectASPNETVersion(url, method, resHeaders) {
    if (!resHeaders) return;
    const xpb = resHeaders['x-powered-by'] || resHeaders['X-Powered-By'] || '';
    const xaspnet = resHeaders['x-aspnet-version'] || resHeaders['X-AspNet-Version'] || '';

    const combined = xpb + ' ' + xaspnet;
    const match = combined.match(/(ASP\.NET[\s/]*([\d.]+)?|\.NET ([\d.]+))/i);
    if (match) {
        _emit('ASP.NET Version Disclosure', url, {
            type: 'ASP.NET Version Disclosure',
            severity: 'Low',
            cvss_score: 5.3,
            evidence: `X-Powered-By: ${xpb}\nX-AspNet-Version: ${xaspnet}`,
            explanation: `The server advertises its ASP.NET framework version (${match[0].trim()}) via response headers.`,
            impact: 'Enables targeted attacks against known ASP.NET framework vulnerabilities for the disclosed version.',
            prevention: 'Remove X-Powered-By and X-AspNet-Version headers in Web.config: <httpRuntime enableVersionHeader="false">.',
            method,
        });
    }
}

// ── 6. Debug Mode Detection ────────────────────────────────────────────────
const DEBUG_REGEX = /\[Exception details are only displayed to the browser from the local machine\]|customErrors mode|compilation debug="true"|ASP\.NET Debugging|Microsoft Visual Studio|in debug mode|Trace\.axd|\bTRACE\b/i;
const DEBUG_BODY_REGEX = /compilationDebug|System\.Web\.HttpException|Object reference not set|NullReferenceException|at System\.(Web|Data|Collections)\./i;

function detectDebugMode(url, method, body, resHeaders) {
    if (!body) return;
    const bodyCheck = DEBUG_REGEX.test(body) || DEBUG_BODY_REGEX.test(body);

    // Check for ASP.NET Trace feature
    const traceEnabled = (body.includes('Trace.axd') || body.includes('Trace Information'));

    if (bodyCheck || traceEnabled) {
        _emit('Debug Mode Enabled', url, {
            type: 'Debug Mode Enabled',
            severity: 'Medium',
            cvss_score: 5.3,
            evidence: traceEnabled 
                ? 'ASP.NET Trace (Trace.axd) appears to be enabled.'
                : 'debug="true" or verbose ASP.NET error page detected in response.',
            explanation: 'The application is running with debug compilation or trace enabled, exposing verbose internal information on errors.',
            impact: 'Reveals server paths, variable states, query strings, and session data to potential attackers.',
            prevention: 'In Web.config set <compilation debug="false"> and <trace enabled="false"> for production.',
            method,
        });
    }
}

// ── 7. Internal IP Disclosure ──────────────────────────────────────────────
const INTERNAL_IP_REGEX = /\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|::1)\b/g;

function detectInternalIP(url, method, body) {
    if (!body) return;
    const matches = [...new Set(body.match(INTERNAL_IP_REGEX) || [])];
    if (matches.length > 0) {
        _emit('Internal IP Disclosure', url, {
            type: 'Internal IP Disclosure',
            severity: 'Low',
            cvss_score: 5.3,
            evidence: `Internal IP addresses found: ${matches.join(', ')}`,
            explanation: 'The application leaks private IPv4 network addresses, revealing internal topology.',
            impact: 'Assists in lateral movement and internal scanning by providing network details.',
            prevention: 'Review responses for leaked internal network signatures.',
            method,
        });
    }
}

// ── 8. HSTS Missing ───────────────────────────────────────────────────────
function detectMissingHSTS(url, method, resHeaders) {
    if (!url.startsWith('https')) return; // HSTS is only applicable over HTTPS
    if (!resHeaders) return;
    const hsts = resHeaders['strict-transport-security'] || resHeaders['Strict-Transport-Security'];
    if (!hsts) {
        _emit('Missing HSTS', url, {
            type: 'Missing HSTS',
            severity: 'Medium',
            cvss_score: 5.3,
            evidence: 'Strict-Transport-Security header is absent.',
            explanation: 'The application uses HTTPS but lacks HSTS protection, allowing protocol downgrade attacks.',
            impact: 'Protocol downgrade (SSL Stripping) allows MITM interception.',
            prevention: 'Implement Strict-Transport-Security header with a long max-age.',
            method,
            confidence_score: 95
        });
    }
}

// ── 9. X-Frame-Options Missing ────────────────────────────────────────────
function detectMissingXFrameOptions(url, method, resHeaders) {
    if (!resHeaders) return;
    const xfo = resHeaders['x-frame-options'] || resHeaders['X-Frame-Options'];
    const csp = resHeaders['content-security-policy'] || resHeaders['Content-Security-Policy'] || '';
    // CSP frame-ancestors is an equivalent replacement
    if (!xfo && !csp.includes('frame-ancestors')) {
        _emit('Missing X-Frame-Options', url, {
            type: 'Missing X-Frame-Options',
            severity: 'Medium',
            cvss_score: 5.3,
            evidence: 'X-Frame-Options header is absent and CSP does not contain frame-ancestors.',
            explanation: 'Without X-Frame-Options or CSP frame-ancestors, this page can be embedded in an iframe on any domain.',
            impact: 'Clickjacking attacks where victims are tricked into clicking hidden page elements.',
            prevention: 'Add: X-Frame-Options: DENY  (or use CSP: frame-ancestors \'self\')',
            method,
        });
    }
}

// ── 10. Content-Security-Policy Missing ───────────────────────────────────
function detectMissingCSP(url, method, resHeaders) {
    if (!resHeaders) return;
    const csp = resHeaders['content-security-policy'] || resHeaders['Content-Security-Policy'];
    if (!csp) {
        _emit('Missing CSP', url, {
            type: 'Missing CSP',
            severity: 'Medium',
            cvss_score: 5.3,
            evidence: 'Content-Security-Policy header is absent from the response.',
            explanation: 'Without a Content Security Policy, the browser does not restrict which resources can execute on this page.',
            impact: 'Increases XSS attack surface and enables data injection attacks.',
            prevention: 'Implement a strict CSP header: Content-Security-Policy: default-src \'self\'',
            method,
        });
    }
}

// ── 11. Cleartext HTTP Transmission ──────────────────────────────────────
function detectCleartextTransmission(url, method) {
    if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
        _emit('Cleartext Transmission', url, {
            type: 'Cleartext Transmission',
            severity: 'Medium',
            cvss_score: 5.9,
            evidence: `Target URL uses cleartext HTTP: ${url}`,
            explanation: 'Sensitive data including session tokens and form values is transmitted without TLS encryption.',
            impact: 'Network eavesdroppers can capture credentials, session tokens, and personal data in transit.',
            prevention: 'Redirect all HTTP traffic to HTTPS. Use HSTS to prevent downgrade.',
            method,
        });
    }
}

// ── Main Entry Point ──────────────────────────────────────────────────────
/**
 * Run all specialized detectors against a given request/response context.
 * @param {Object} ctx - { url, method, status, resHeaders, resBody, reqBody, baseBody, payload }
 */
function runAll(ctx) {
    try {
        const { url, method, status, resHeaders = {}, resBody = '', baseBody = '', payload = '' } = ctx;
        if (!url) return;

        detectStackTrace(url, method, resBody, baseBody, status);
        detectInsecureCookies(url, method, resHeaders);
        detectIISVersion(url, method, resHeaders);
        detectASPNETVersion(url, method, resHeaders);
        detectDebugMode(url, method, resBody, resHeaders);
        detectInternalIP(url, method, resBody);
        detectMissingHSTS(url, method, resHeaders);
        detectMissingXFrameOptions(url, method, resHeaders);
        detectMissingCSP(url, method, resHeaders);
        detectCleartextTransmission(url, method);

        // XSS reflection check (active payload context)
        if (payload) {
            detectXSSReflection(url, method, payload, resBody, baseBody);
        }
    } catch (e) {
        console.error('[SpecializedDetectors] Error:', e.message);
    }
}

/** Clear dedup cache (call at start of each scan) */
function resetDedupCache() {
    _emitted.clear();
}

module.exports = {
    runAll,
    resetDedupCache,
    detectStackTrace,
    detectXSSReflection,
    detectInsecureCookies,
    detectIISVersion,
    detectASPNETVersion,
    detectDebugMode,
    detectInternalIP,
    detectMissingHSTS,
    detectMissingXFrameOptions,
    detectMissingCSP,
    detectCleartextTransmission,
};
