'use strict';
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

class Crawler {
    constructor() {
        this.timeout = 15000;
        this.maxDepth = 3;
        this.maxPages = 50; // safety cap
    }

    async crawl(startUrl, method = 'GET', headers = {}, body = '') {
        const visited = new Set();
        const allLinks = [];
        const allForms = [];

        // BFS crawl queue: { url, depth }
        const queue = [{ url: startUrl, depth: 0 }];
        visited.add(startUrl);

        while (queue.length > 0 && visited.size <= this.maxPages) {
            const { url, depth } = queue.shift();

            try {
                const result = await this._fetchPage(url, method, headers, body);
                if (!result) continue;

                // Collect forms from this page
                result.forms.forEach(f => allForms.push(f));

                // Collect and filter links
                for (const link of result.links) {
                    if (visited.has(link)) continue;

                    // Only follow same-origin links for crawl depth > 0
                    try {
                        const base = new URL(startUrl);
                        const target = new URL(link);
                        const sameOrigin = base.hostname === target.hostname;

                        if (sameOrigin) {
                            visited.add(link);
                            allLinks.push(link);

                            if (depth < this.maxDepth) {
                                queue.push({ url: link, depth: depth + 1 });
                            }
                        }
                    } catch {}
                }
            } catch (e) {
                console.error('[Crawler] Error crawling', url, ':', e.message);
            }
        }

        console.log(`[Crawler] Finished. Visited: ${visited.size} pages, Found: ${allLinks.length} links, ${allForms.length} forms.`);
        return { url: startUrl, links: allLinks, forms: allForms };
    }

    async _fetchPage(url, method = 'GET', headers = {}, body = '') {
        try {
            const reqConfig = {
                method,
                url,
                headers: { ...headers, 'x-miniburp-internal': 'crawler', 'User-Agent': 'Mozilla/5.0 (compatible; MiniBurpScanner/1.0)' },
                timeout: this.timeout,
                validateStatus: () => true,
                maxRedirects: 5
            };
            if (method === 'POST') reqConfig.data = body;

            const res = await axios(reqConfig);
            const html = typeof res.data === 'string' ? res.data : '';

            return {
                url,
                status: res.status,
                headers: res.headers,
                body: html,
                links: this.extractLinks(html, url),
                forms: this.extractForms(html, url)
            };
        } catch (e) {
            console.error('[Crawler] Fetch error for', url, ':', e.message);
            return null;
        }
    }

    extractLinks(html, baseUrl) {
        if (typeof html !== 'string') return [];
        const $ = cheerio.load(html);
        const links = new Set();

        // Extract <a href> links
        $('a[href]').each((_, el) => {
            let href = $(el).attr('href');
            if (!href || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('#')) return;
            try {
                const resolved = new URL(href, baseUrl).href;
                links.add(resolved);
            } catch {}
        });

        // Extract form actions
        $('form[action]').each((_, el) => {
            const action = $(el).attr('action');
            if (!action || action.startsWith('javascript:')) return;
            try {
                links.add(new URL(action, baseUrl).href);
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
                links.add(resolved);
            } catch {}
        }

        return Array.from(links);
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
