'use strict';
const crawler = require('./crawlerEngine');
const store   = require('./endpointStore');
const detector = require('./detectionEngine');
const db      = require('../database');

let isRunning    = false;
let currentUrl   = '';
let testedCount  = 0;
let scanCallback = null;
let ioInstance   = null;

function setIO(io) {
    ioInstance = io;
}

function _emitProgress(state, message) {
    let total = 0;
    for (const ep of store.endpoints.values()) total++;
    const progress = total > 0 ? Math.round((testedCount / total) * 100) : 0;

    const payload = {
        state, message, currentUrl, testedCount, isRunning,
        // UI-expected fields
        progress,
        scanned: testedCount,
        discovered: total,
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

    isRunning    = true;
    scanCallback = updateCallback;
    store.reset();
    testedCount = 0;

    _emitProgress('CRAWLING', `Starting BFS crawl of ${targetUrl}...`);

    try {
        // ── Phase 1: BFS Crawler ──────────────────────────────────────────
        store.add(targetUrl, 'GET', _extractUrlParams(targetUrl));

        const crawlResult = await crawler.crawl(targetUrl, 'GET');

        if (crawlResult) {
            // Add discovered links
            for (const link of crawlResult.links) {
                if (_isValidUrl(link)) {
                    const params = _extractUrlParams(link);
                    store.add(link, 'GET', params);
                }
            }

            // Add discovered forms
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
        const concurrency = 3;

        await new Promise((resolve) => {
            const worker = async () => {
                while (isRunning) {
                    const ep = store.getUntested();
                    if (!ep) break;

                    currentUrl = ep.url;

                    // Skip static assets — no injection surface
                    const STATIC_EXT = /\.(css|js|mjs|png|jpg|jpeg|gif|webp|avif|svg|ico|bmp|woff|woff2|ttf|eot|otf|mp4|mp3|pdf|zip|tar|gz|wasm)(\?.*)?$/i;
                    if (STATIC_EXT.test(ep.url)) {
                        testedCount++;
                        await new Promise(r => setTimeout(r, 5));
                        continue;
                    }

                    _emitProgress('TESTING', `[${testedCount + 1}/${total}] Testing: ${ep.url}`);

                    try {
                        const findings = await detector.testEndpoint(ep);

                        if (findings && findings.length > 0) {
                            for (const f of findings) {
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
                                    timestamp:   new Date().toISOString()
                                };

                                db.saveFinding(findingObj);
                                if (ioInstance) ioInstance.emit('finding:new', findingObj);
                            }
                        }
                    } catch (e) {
                        console.error('[ScanEngine] testEndpoint error:', e.message);
                    }

                    testedCount++;
                    await new Promise(r => setTimeout(r, 20));
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
    _emitProgress('DONE', `Scan complete. Tested ${testedCount} endpoints.`);
}

function stopScan() {
    isRunning = false;
    _emitProgress('STOPPED', 'Scan stopped by user.');
}

function getScanStatus() {
    let pending = 0;
    let total   = 0;
    for (const ep of store.endpoints.values()) {
        total++;
        if (!ep.tested) pending++;
    }
    const progress = total > 0 ? Math.round((testedCount / total) * 100) : 0;
    return {
        isRunning,
        testedCount,
        currentUrl,
        pendingTests: pending,
        totalEndpoints: total,
        // UI-expected aliases
        progress,
        scanned: testedCount,
        discovered: total,
    };
}

module.exports = { startScan, stopScan, getScanStatus, setIO };
