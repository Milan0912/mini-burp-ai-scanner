'use strict';

const puppeteer = require('puppeteer');

/**
 * GhostEngine.js
 * ==============
 * Headless browser engine for DOM-XSS detection and dynamic modeling.
 * Fulfills Task 4.
 */

class GhostEngine {
    constructor() {
        this.browser = null;
    }

    async init() {
        if (!this.browser) {
            this.browser = await puppeteer.launch({
                headless: "new",
                executablePath: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors']
            });
        }
    }

    async scanDOM(url, payload) {
        await this.init();
        const page = await this.browser.newPage();
        let alerted = false;

        try {
            page.on('dialog', async dialog => {
                alerted = true;
                await dialog.dismiss();
            });

            const mutatedUrl = new URL(url);
            // Example: Inject into hash or query for DOM XSS
            mutatedUrl.hash = payload;
            
            await page.goto(mutatedUrl.href, { waitUntil: 'load', timeout: 5000 });
            await page.waitForTimeout(500); // Short wait for internal JS

            return { alerted, body: await page.content() };
        } catch (e) {
            return { alerted: false, error: e.message };
        } finally {
            await page.close();
        }
    }

    async captureDynamicBehavior(url) {
        try {
            await this.init();
            const page = await this.browser.newPage();
            const dynamicData = { links: [], forms: [], storage: {} };

            try {
                await page.goto(url, { waitUntil: 'load', timeout: 30000 });
                
                dynamicData.links = await page.$$eval('a', el => el.map(a => a.href));
                dynamicData.storage = await page.evaluate(() => ({
                    local: { ...localStorage },
                    session: { ...sessionStorage }
                }));

                return dynamicData;
            } catch (e) {
                console.warn(`[GhostEngine] Dynamic capture failed for ${url}: ${e.message}`);
                return dynamicData; // Return empty but continue
            } finally {
                await page.close();
            }
        } catch (e) {
            console.warn('[GhostEngine] Browser init failed:', e.message);
            return { links: [], forms: [], storage: {} };
        }
    }

    async shutdown() {
        if (this.browser) await this.browser.close();
    }
}

module.exports = new GhostEngine();
