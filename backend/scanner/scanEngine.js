'use strict';
const crawler = require('./crawlerEngine');
const store = require('./endpointStore');
const detector = require('./detectionEngine');
const exploitEngine = require('./exploitEngine');
const db = require('../database');
const autoAI = require('../ai/autoAI');

let isRunning = false;
let currentUrl = '';
let testedCount = 0;
let scanCallback = null;
let ioInstance = null;

let rawFindingsCount = 0;
let verifiedFindingsCount = 0;
let falsePositivesRemoved = 0;

function shouldSaveFinding(f) {
    if (!f) return false;
    if (!f.evidence && !f.proof) return false;
    const conf = (f.confidence || '').toUpperCase();
    if (!['VERIFIED', 'LIKELY', 'INFORMATIONAL', 'INFO'].includes(conf)) return false;
    return true;
}

function setIO(io) {
    ioInstance = io;
}

function _emitProgress(state, message, extra = {}) {
    const stats = store.getStats();
    const combinedStats = {
        ...stats,
        testedParams: detector.stats.testedParams || 0,
        testedPayloads: detector.stats.testedPayloads || 0,
    };
    // Cap testedCount at total to avoid UI overflow (e.g. [67/66])
    const displayCount = stats.total > 0 ? Math.min(testedCount, stats.total) : testedCount;
    const progress = stats.total > 0 ? Math.round((displayCount / stats.total) * 100) : 0;

    const payload = {
        state,
        message,
        currentUrl,
        testedCount: displayCount,
        isRunning,
        stats: combinedStats,
        // UI-expected fields
        progress: Math.min(progress, 100),
        scanned: displayCount,
        discovered: stats.total,
        pendingTests: stats.untested,
        ...extra
    };
    if (scanCallback) scanCallback(payload);
    if (ioInstance) {
        ioInstance.emit('scan:log', payload);
        ioInstance.emit('scanner:update', payload);
    }
    console.log(`[ScanEngine][${state}] ${message}`);
}

function _isValidUrl(url) {
    try {
        const u = new URL(url);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
}

function _extractUrlParams(url) {
    try {
        const u = new URL(url);
        const params = {};
        u.searchParams.forEach((v, k) => { params[k] = v; });
        return params;
    } catch {
        return {};
    }
}

async function startScan(targetUrl, options = {}, updateCallback) {
    if (isRunning) {
        console.log('[ScanEngine] Scan already running, ignoring start request.');
        return;
    }

    // Validate target URL
    if (!_isValidUrl(targetUrl)) {
        console.error('[ScanEngine] Invalid target URL:', targetUrl);
        if (updateCallback) updateCallback({ state: 'ERROR', message: `Invalid URL: ${targetUrl}` });
        return;
    }

    isRunning = true;
    scanCallback = updateCallback;
    store.reset();
    testedCount = 0;
    rawFindingsCount = 0;
    verifiedFindingsCount = 0;
    falsePositivesRemoved = 0;
    detector.resetStats();
    crawler.scanCancelled = false;
    detector.scanCancelled = false;

    const seenFindings = new Set();

    _emitProgress('CRAWLING', `Starting BFS crawl of ${targetUrl}...`);

    try {
        // ── Phase 1: BFS Crawler ──────────────────────────────────────────
        store.add(targetUrl, 'GET', _extractUrlParams(targetUrl));

        const crawlOptions = {
            maxDepth: Number.isInteger(options.maxDepth) ? options.maxDepth : 3,
            maxPages: Number.isInteger(options.maxPages) ? options.maxPages : 50,
            timeout: Number.isInteger(options.timeout) ? options.timeout : 15000,
            allowedDomains: Array.isArray(options.allowedDomains) ? options.allowedDomains : [],
        };

        const crawlResult = await crawler.crawl(targetUrl, 'GET', {}, '', crawlOptions, (progress) => {
            if (progress.type === 'link') {
                if (_isValidUrl(progress.url)) {
                    const params = _extractUrlParams(progress.url);
                    store.add(progress.url, 'GET', params);
                }
            } else if (progress.type === 'form') {
                if (_isValidUrl(progress.form.url)) {
                    store.add(progress.form.url, progress.form.method, progress.form.params || {});
                }
            }
            _emitProgress('CRAWLING', `Crawl in progress... Discovered ${store.getStats().total} endpoints`);
        });

        if (crawlResult) {
            // Ensure all crawler links are in the store
            for (const link of crawlResult.links) {
                if (_isValidUrl(link)) {
                    const params = _extractUrlParams(link);
                    store.add(link, 'GET', params);
                }
            }

            // Ensure all crawler forms are in the store
            for (const form of crawlResult.forms) {
                if (_isValidUrl(form.url)) {
                    store.add(form.url, form.method, form.params || {});
                }
            }
        }

        const total = store.endpoints.size;
        _emitProgress('TESTING', `Crawl complete. Discovered ${total} endpoints. Scanning...`);

        if (total === 0) {
            _emitProgress('DONE', 'No endpoints found.');
            isRunning = false;
            return;
        }

        // ── Phase 2: Parallel Scan Loop ───────────────────────────────────
        const concurrency = Number.isInteger(options.concurrency) && options.concurrency > 0 ? Math.min(options.concurrency, 10) : 3;
        const throttleMs = Number.isInteger(options.throttleMs) ? options.throttleMs : 20;

        await new Promise((resolve) => {
            const worker = async () => {
                while (isRunning) {
                    const ep = store.getNextUntested();
                    if (!ep) break;

                    // Skip static assets — no injection surface
                    const STATIC_EXT = /\.(css|js|mjs|png|jpg|jpeg|gif|webp|avif|svg|ico|bmp|woff|woff2|ttf|eot|otf|mp4|mp3|pdf|zip|tar|gz|wasm)(\?.*)?$/i;
                    if (STATIC_EXT.test(ep.url)) {
                        testedCount++;
                        await new Promise(r => setTimeout(r, 5));
                        continue;
                    }

                    currentUrl = ep.url;
                    const stats = store.getStats();
                    _emitProgress('TESTING', `[${stats.tested + 1}/${stats.total}] Testing: ${ep.url}`);
                    try {
                        const findings = await detector.testEndpoint(ep, (testName, paramName, payloadVal) => {
                            _emitProgress('TESTING', `[${stats.tested + 1}/${stats.total}] Testing: ${ep.url}`, {
                                currentTest: testName,
                                currentParam: paramName,
                                currentPayload: payloadVal
                            });
                        });

                        if (findings && findings.length > 0) {
                            for (const f of findings) {
                                rawFindingsCount++;

                                let key;
                                if (f.type.includes('Missing') || f.type.includes('Server Version')) {
                                    try {
                                        const domain = new URL(ep.url).hostname;
                                        key = `${f.type}|${domain}`;
                                    } catch {
                                        key = `${f.type}|${ep.url}|${ep.method}|${f.parameter}`;
                                    }
                                } else {
                                    key = `${f.type}|${ep.url}|${ep.method}|${f.parameter}`;
                                }
                                
                                if (seenFindings.has(key)) continue;
                                seenFindings.add(key);

                                if (db.findingExists(f.type, ep.url, ep.method, f.parameter)) continue;

                                if (!shouldSaveFinding(f)) {
                                    console.log(`[SCANNER] Ignored unverified finding: ${f.type}`);
                                    falsePositivesRemoved++;
                                    continue;
                                }

                                const responseSnippet = f.injectedResponseBody || "No response body available";
                                delete f.injectedResponseBody;

                                try {
                                    const fpCheck = await autoAI.checkFalsePositive(f, responseSnippet);
                                    if (fpCheck && fpCheck.is_false_positive && fpCheck.confidence > 80) {
                                        console.log(`[SCANNER] AI discarded false positive: ${f.type}`);
                                        falsePositivesRemoved++;
                                        continue;
                                    }
                                } catch (e) {
                                    console.warn('[ScanEngine] AI False Positive check failed:', e.message);
                                }

                                verifiedFindingsCount++;

                                _emitProgress('FINDING', `✅ ${f.type} | ${f.parameter} | ${f.confidence} | ${ep.url}`);

                                const findingObj = {
                                    id:          Date.now().toString() + '-' + Math.random().toString(36).substr(2, 5),
                                    url:         f.endpoint || ep.url,
                                    method:      ep.method,
                                    title:       `[${f.confidence}] ${f.type}`,
                                    description: `Parameter: '${f.parameter}'. Proof: ${f.proof}. Severity: ${f.severity}. Score: ${f.score}`,
                                    payload:     f.payload,
                                    confidence:  f.confidence,
                                    severity:    f.severity,
                                    timestamp:   new Date().toISOString(),
                                    type:        f.type,
                                    parameter:   f.parameter,
                                    endpoint:    ep.url,
                                    score:       f.score,
                                    evidence:    f.evidence || f.proof,
                                    reasoning:   f.reasoning || '',
                                    cvss_score:  f.score ? parseFloat((f.score / 10).toFixed(1)) : 0.0
                                };

                                // ── EXPLOITATION PHASE (DISABLED FOR STABILITY) ──
                                // Metasploit integration disabled for demo stability
                                if (false && options.exploitationEnabled !== false) {
                                    try {
                                        _emitProgress('EXPLOITING', `Attempting exploitation of ${f.type}...`);
                                        
                                        const exploitResult = await exploitEngine.exploitFinding(
                                            {
                                                type: f.type,
                                                endpoint: ep.url,
                                                parameter: f.parameter,
                                                payload: f.payload,
                                                subtype: f.subtype || 'generic'
                                            },
                                            {
                                                domainWhitelist: options.domainWhitelist || [],
                                                timeout: options.exploitTimeout || 30000
                                            }
                                        );

                                        // Update finding with exploitation results
                                        if (exploitResult.exploited) {
                                            findingObj.exploited = true;
                                            findingObj.exploit_proof = exploitResult.dataExtracted;
                                            findingObj.metasploit_module = exploitResult.moduleUsed;
                                            findingObj.exploitation_timestamp = new Date().toISOString();
                                            findingObj.confidence = 'VERIFIED_EXPLOITED';
                                            
                                            _emitProgress('FINDING', `✅✅ EXPLOITED ${f.type} | ${f.parameter} | VERIFIED | ${ep.url}`);
                                            console.log(`[ScanEngine] Exploitation successful for ${f.type}`);
                                        } else if (exploitResult.error) {
                                            console.warn(`[ScanEngine] Exploitation failed for ${f.type}: ${exploitResult.error}`);
                                        }

                                        // Log the exploitation attempt
                                        db.saveExploitLog({
                                            targetUrl: ep.url,
                                            vulnerabilityType: f.type,
                                            parameter: f.parameter,
                                            moduleUsed: exploitResult.moduleUsed,
                                            success: exploitResult.exploited,
                                            confidence: exploitResult.confidence,
                                            executionTime: exploitResult.executionTime,
                                            output: exploitResult.output,
                                            evidence: exploitResult.success ? 'Exploitation successful' : 'Exploitation failed'
                                        });
                                    } catch (e) {
                                        console.warn('[ScanEngine] Exploitation error:', e.message);
                                        // Don't crash the scanner if exploitation fails
                                    }
                                }

                                // Attach AI analysis
                                try {
                                    const aiAnalysis = await autoAI.analyzeFinding(findingObj);
                                    findingObj.aiAnalysis = aiAnalysis;
                                } catch (e) {
                                    console.warn('[ScanEngine] AI analysis failed:', e.message);
                                }

                                db.saveFinding(findingObj);

                                if (ioInstance) ioInstance.emit('finding:new', findingObj);
                            }
                        }
                    } catch (e) {
                        console.error('[ScanEngine] testEndpoint error:', e.message);
                    }

                    testedCount++;
                    await new Promise(r => setTimeout(r, throttleMs));
                }
            };

            const workers = [];
            for (let i = 0; i < concurrency; i++) workers.push(worker());
            Promise.all(workers).then(() => resolve());
        });

    } catch (err) {
        console.error('[ScanEngine] Fatal error:', err.message);
    }

    isRunning = false;

    const dStats = detector.stats;
    const finalReportStr = `
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    FINAL SCAN REPORT
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Before fix findings: ${rawFindingsCount}
    After fix findings: ${verifiedFindingsCount}
    VERIFIED findings: ${verifiedFindingsCount}
    False positives removed: ${falsePositivesRemoved}
    Skipped tests: ${dStats.skippedTests}
    Noise ignored: ${dStats.noiseIgnored}
    Duplicates ignored: ${dStats.duplicatesIgnored}
    Payloads adapted: ${dStats.payloadAdapted}
    WAF detections: ${dStats.wafDetected}
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
    
    console.log('[SCANNER]', finalReportStr);

    _emitProgress('DONE', `Scan complete. Tested ${testedCount} endpoints.`);

    try {
        const allFindings = db.getFindings();
        const summary = await autoAI.generateScanSummary(allFindings);
        if (ioInstance) {
            ioInstance.emit('scanner:summary', summary);
        }
    } catch (e) {
        console.error('[ScanEngine] Failed to generate AI scan summary:', e.message);
    }
}

function stopScan() {
    isRunning = false;
    crawler.scanCancelled = true;
    detector.scanCancelled = true;
    _emitProgress('STOPPED', 'Scan stopped by user.');
}

function getScanStatus() {
    const stats = store.getStats();
    const displayCount = stats.total > 0 ? Math.min(testedCount, stats.total) : testedCount;
    const progress = stats.total > 0 ? Math.round((displayCount / stats.total) * 100) : 0;
    return {
        isRunning,
        testedCount: displayCount,
        currentUrl,
        pendingTests: stats.untested,
        totalEndpoints: stats.total,
        stats,
        // UI-expected aliases
        progress: Math.min(progress, 100),
        scanned: displayCount,
        discovered: stats.total,
    };
}

module.exports = { startScan, stopScan, getScanStatus, setIO };
