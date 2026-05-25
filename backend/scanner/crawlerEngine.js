'use strict';
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

const STATIC_EXT = /\.(png|jpg|jpeg|svg|gif|mp4|ttf|woff|woff2|eot|otf|ico|css)(\?.*)?$/i;

class Crawler {
    constructor() {
        this.timeout = 15000;
        this.defaultMaxDepth = 3;
        this.defaultMaxPages = 50;
        this.scanCancelled = false;
    }

    async crawl(startUrl, method = 'GET', headers = {}, body = '', options = {}, onProgress = null) {
        const config = {
            maxDepth: Number.isInteger(options.maxDepth) ? options.maxDepth : this.defaultMaxDepth,
            maxPages: Number.isInteger(options.maxPages) ? options.maxPages : this.defaultMaxPages,
            timeout: Number.isInteger(options.timeout) ? options.timeout : this.timeout,
            allowedDomains: Array.isArray(options.allowedDomains) ? options.allowedDomains : [],
        };

        const progressCb = onProgress || options.onProgress || null;

        const visited = new Set();
        const allLinks = new Set();
        const allForms = [];
        const jsEndpoints = new Set();
        const queue = [{ url: startUrl, depth: 0 }];
        let pagesCrawled = 0;
        const origin = new URL(startUrl).origin;
        await this.attemptLogin(origin, config.timeout);

        visited.add(startUrl);
        if (progressCb) progressCb({ type: 'link', url: startUrl });

        const robots = await this.fetchRobots(origin, config.timeout);
        const sitemapUrls = await this.fetchSitemap(origin, config.timeout);

        for (const sitemapUrl of sitemapUrls) {
            if (!visited.has(sitemapUrl) && this.isAllowedUrl(sitemapUrl, origin, config.allowedDomains) && this.canCrawlPath(sitemapUrl, robots)) {
                if (STATIC_EXT.test(sitemapUrl)) continue;
                visited.add(sitemapUrl);
                queue.push({ url: sitemapUrl, depth: 0 });
                if (progressCb) progressCb({ type: 'link', url: sitemapUrl });
            }
        }

        while (queue.length > 0 && pagesCrawled < config.maxPages) {
            if (this.scanCancelled) break;
            const { url, depth } = queue.shift();
            if (depth > config.maxDepth) continue;
            if (!this.isAllowedUrl(url, origin, config.allowedDomains)) continue;
            if (!this.canCrawlPath(url, robots)) continue;

            try {
                const result = await this._fetchPage(url, method, headers, body, config.timeout);
                if (!result) continue;

                pagesCrawled += 1;
                result.forms.forEach((form) => {
                    allForms.push(form);
                    if (progressCb) progressCb({ type: 'form', form });
                });
                result.links.forEach((link) => {
                    if (!allLinks.has(link)) {
                        allLinks.add(link);
                        if (progressCb) progressCb({ type: 'link', url: link });
                    }
                });
                result.jsEndpoints.forEach((link) => {
                    if (!jsEndpoints.has(link)) {
                        jsEndpoints.add(link);
                        if (progressCb) progressCb({ type: 'link', url: link });
                    }
                });

                for (const link of [...result.links, ...result.jsEndpoints]) {
                    if (visited.has(link)) continue;
                    if (!this.isAllowedUrl(link, origin, config.allowedDomains)) continue;
                    if (!this.canCrawlPath(link, robots)) continue;
                    visited.add(link);
                    if (depth < config.maxDepth) {
                        queue.push({ url: link, depth: depth + 1 });
                    }
                }
            } catch (e) {
                console.error('[Crawler][crawl] Error:', e.message);
            }
        }

        const crawlStats = {
            pageCount: pagesCrawled,
            linkCount: allLinks.size,
            formCount: allForms.length,
            jsEndpointCount: jsEndpoints.size,
            maxDepth: config.maxDepth,
            maxPages: config.maxPages,
        };

        console.log(`[Crawler] Finished. Visited: ${visited.size} pages, Found: ${allLinks.size} links, ${allForms.length} forms, ${jsEndpoints.size} js endpoints.`);
        return {
            url: startUrl,
            links: Array.from(allLinks),
            forms: allForms,
            jsEndpoints: Array.from(jsEndpoints),
            crawlStats,
        };
    }

    async attemptLogin(origin, timeout = 15000) {
        try {
            const sessionManager = require('../core/sessionManager');
            if (origin.includes('ginandjuice.shop')) {
                console.log('[Crawler] Performing automated login for ginandjuice.shop...');
                const loginPageUrl = `${origin}/login`;
                const getRes = await axios.get(loginPageUrl, {
                    timeout,
                    validateStatus: () => true,
                    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; MiniBurpScanner/1.0)' }
                });
                
                if (getRes.headers['set-cookie']) {
                    sessionManager.updateCookies(new URL(loginPageUrl).host, getRes.headers['set-cookie']);
                }
                
                let csrfToken = '';
                const html = getRes.data || '';
                const $ = cheerio.load(html);
                const csrfInput = $('input[name="csrf"]').val() || $('input[name="_csrf"]').val() || $('input[name="token"]').val();
                if (csrfInput) {
                    csrfToken = csrfInput;
                }
                
                const postData = new URLSearchParams();
                postData.append('username', 'carlos');
                postData.append('password', 'hunter2');
                if (csrfToken) {
                    postData.append('csrf', csrfToken);
                }
                
                const jar = sessionManager.getCookieHeader(new URL(loginPageUrl).host);
                const postHeaders = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (compatible; MiniBurpScanner/1.0)'
                };
                if (jar) postHeaders['cookie'] = jar;
                
                const postRes = await axios.post(loginPageUrl, postData.toString(), {
                    timeout,
                    validateStatus: () => true,
                    maxRedirects: 0,
                    headers: postHeaders
                });
                
                if (postRes.headers['set-cookie']) {
                    sessionManager.updateCookies(new URL(loginPageUrl).host, postRes.headers['set-cookie']);
                    console.log('[Crawler] Automated login cookies captured!');
                } else if (postRes.status === 302) {
                    if (postRes.headers['set-cookie']) {
                        sessionManager.updateCookies(new URL(loginPageUrl).host, postRes.headers['set-cookie']);
                    }
                    console.log('[Crawler] Automated login redirect received.');
                }
            }
        } catch (e) {
            console.error('[Crawler] Automated login error:', e.message);
        }
    }

    async _fetchPage(url, method = 'GET', headers = {}, body = '', timeout = 15000) {
        try {
            const u = new URL(url);
            const reqConfig = {
                method,
                url,
                headers: { ...headers, 'x-miniburp-internal': 'crawler', 'User-Agent': 'Mozilla/5.0 (compatible; MiniBurpScanner/1.0)' },
                timeout,
                validateStatus: () => true,
                maxRedirects: 5
            };
            if (method === 'POST') reqConfig.data = body;

            const sessionManager = require('../core/sessionManager');
            const jar = sessionManager.getCookieHeader(u.host);
            if (jar) {
                reqConfig.headers['cookie'] = jar;
            }

            const res = await axios(reqConfig);
            
            if (res.headers['set-cookie']) {
                sessionManager.updateCookies(u.host, res.headers['set-cookie']);
            }

            const html = typeof res.data === 'string' ? res.data : ' ';

            return {
                url,
                status: res.status,
                headers: res.headers,
                body: html,
                links: this.extractLinks(html, url),
                forms: this.extractForms(html, url),
                jsEndpoints: this.extractJsEndpoints(html, url),
            };
        } catch (e) {
            console.error('[Crawler][_fetchPage] Error:', e.message);
            return null;
        }
    }

    async fetchRobots(origin, timeout = 15000) {
        try {
            const res = await axios.get(`${origin}/robots.txt`, {
                timeout,
                validateStatus: () => true,
            });
            if (res.status !== 200 || typeof res.data !== 'string') return null;
            const rules = { allow: [], disallow: [] };
            let active = false;
            for (const rawLine of res.data.split(/\r?\n/)) {
                const line = rawLine.trim();
                if (!line || line.startsWith('#')) continue;
                const parts = line.split(':', 2);
                if (parts.length < 2) continue;
                const key = parts[0].trim().toLowerCase();
                const value = parts[1].trim();
                if (key === 'user-agent') {
                    active = value === '*' || value.toLowerCase().includes('miniburp');
                }
                if (!active) continue;
                if (key === 'allow') rules.allow.push(value);
                if (key === 'disallow') rules.disallow.push(value);
            }
            return rules;
        } catch (e) {
            console.error('[Crawler][fetchRobots] Error:', e.message);
            return null;
        }
    }

    async fetchSitemap(origin, timeout = 15000) {
        try {
            const res = await axios.get(`${origin}/sitemap.xml`, {
                timeout,
                validateStatus: () => true,
            });
            if (res.status !== 200 || typeof res.data !== 'string') return [];
            const urls = [];
            const regex = /<loc>(.*?)<\/loc>/gi;
            let match;
            while ((match = regex.exec(res.data)) !== null) {
                try {
                    urls.push(new URL(match[1].trim(), origin).href);
                } catch {}
            }
            return urls;
        } catch (e) {
            console.error('[Crawler][fetchSitemap] Error:', e.message);
            return [];
        }
    }

    canCrawlPath(url, robots) {
        if (!robots) return true;
        try {
            const parsed = new URL(url);
            const path = `${parsed.pathname}${parsed.search}`;
            for (const allow of robots.allow) {
                if (allow && path.startsWith(allow)) return true;
            }
            for (const disallow of robots.disallow) {
                if (!disallow) continue;
                if (disallow === '/' || path.startsWith(disallow)) return false;
            }
            return true;
        } catch {
            return true;
        }
    }

    isAllowedUrl(url, origin, allowedDomains = []) {
        try {
            const target = new URL(url);
            if (!target.href.startsWith(origin)) return false;
            if (STATIC_EXT.test(target.pathname) || STATIC_EXT.test(target.href)) return false;
            if (allowedDomains.length === 0) return true;
            return allowedDomains.some((domain) => {
                const normalized = domain.trim().toLowerCase();
                if (!normalized) return false;
                return target.hostname === normalized || target.hostname.includes(normalized) || target.href.includes(normalized);
            });
        } catch {
            return false;
        }
    }

    extractLinks(html, baseUrl) {
        if (typeof html !== 'string') return [];
        const $ = cheerio.load(html);
        const links = new Set();
        const origin = new URL(baseUrl).origin;

        // Extract <a href> links
        $('a[href]').each((_, el) => {
            let href = $(el).attr('href');
            if (!href || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('#')) return;
            try {
                const resolved = new URL(href, baseUrl).href;
                if (!resolved.startsWith(origin)) return;
                if (STATIC_EXT.test(resolved)) return;
                links.add(resolved);
            } catch {}
        });

        // Extract form actions
        $('form[action]').each((_, el) => {
            const action = $(el).attr('action');
            if (!action || action.startsWith('javascript:')) return;
            try {
                const resolved = new URL(action, baseUrl).href;
                if (!resolved.startsWith(origin)) return;
                if (STATIC_EXT.test(resolved)) return;
                links.add(resolved);
            } catch {}
        });

        // Extract JS fetch/XHR paths — ONLY clean relative paths starting with /
        // Must start with / and NOT contain :// to avoid joining full URLs incorrectly
        const jsPathRegex = /['"`](\/[a-zA-Z0-9_/\-?.&=%]+)['"`]/g;
        let m;
        while ((m = jsPathRegex.exec(html)) !== null) {
            const p = m[1];
            // Skip data URIs, protocol-relative, or anything that looks like full URL
            if (p.includes('://') || p.startsWith('//')) continue;
            try {
                const resolved = new URL(p, baseUrl).href;
                if (!resolved.startsWith(origin)) continue;
                if (STATIC_EXT.test(resolved)) continue;
                links.add(resolved);
            } catch {}
        }

        return Array.from(links);
    }

    extractJsEndpoints(html, baseUrl) {
        if (typeof html !== 'string') return [];
        const urls = new Set();
        const origin = new URL(baseUrl).origin;
        const jsRegex = /(?:fetch|axios\.get|axios\(|router\.push|navigate|window\.location)\(["'`]([^"'`\)]+)/gi;
        let match;
        while ((match = jsRegex.exec(html)) !== null) {
            try {
                const raw = match[1];
                if (!raw || raw.includes('://') || raw.startsWith('//')) continue;
                const resolved = new URL(raw, baseUrl).href;
                if (!resolved.startsWith(origin)) continue;
                if (STATIC_EXT.test(resolved)) continue;
                urls.add(resolved);
            } catch {}
        }

        const jsonRegex = /(window\.__INITIAL_STATE__|window\.__APP_STATE__|__NEXT_DATA__)=\s*({[\s\S]*?})(?:;|\n)/gi;
        while ((match = jsonRegex.exec(html)) !== null) {
            try {
                const parsed = JSON.parse(match[2]);
                this.findUrlsInObject(parsed).forEach((u) => {
                    try {
                        const resolved = new URL(u, baseUrl).href;
                        if (resolved.startsWith(origin) && !STATIC_EXT.test(resolved)) {
                            urls.add(resolved);
                        }
                    } catch {}
                });
            } catch {}
        }

        return Array.from(urls);
    }

    findUrlsInObject(value) {
        const urls = new Set();
        const recurse = (obj) => {
            if (typeof obj === 'string') {
                if (obj.startsWith('/') || obj.startsWith('http')) {
                    urls.add(obj);
                }
                return;
            }
            if (Array.isArray(obj)) {
                obj.forEach(recurse);
                return;
            }
            if (typeof obj === 'object' && obj !== null) {
                Object.values(obj).forEach(recurse);
            }
        };
        recurse(value);
        return urls;
    }

    extractForms(html, baseUrl) {
        if (typeof html !== 'string') return [];
        const $ = cheerio.load(html);
        const forms = [];

        $('form').each((_, el) => {
            const action = $(el).attr('action') || '';
            const method = ($(el).attr('method') || 'GET').toUpperCase();
            let targetUrl = baseUrl;

            try {
                if (action && !action.startsWith('javascript:')) {
                    targetUrl = new URL(action, baseUrl).href;
                }
            } catch {}

            const params = {};
            $(el).find('input, select, textarea').each((_, input) => {
                const name = $(input).attr('name');
                const type = ($(input).attr('type') || '').toLowerCase();
                // Include all named inputs including hidden
                if (name) {
                    if (type === 'checkbox' || type === 'radio') {
                        params[name] = $(input).attr('checked') ? $(input).attr('value') || 'on' : '';
                    } else {
                        params[name] = $(input).val() || $(input).attr('value') || '';
                    }
                }
            });

            if (Object.keys(params).length > 0 || action) {
                forms.push({ url: targetUrl, method, params });
            }
        });

        return forms;
    }
}

module.exports = new Crawler();
