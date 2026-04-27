'use strict';

/**
 * WafDefender.js
 * ==============
 * Detects blocks, rate-limits, and adjusts orchestrator timing.
 * Fulfills Task 7.
 */

class WafDefender {
    constructor() {
        this.baseDelay = 200;
        this.isBlocked = false;
        this.blockCount = 0;
    }

    analyze(response) {
        if (!response) return { action: 'retry', delay: 2000 };

        const { status, body = '' } = response;

        // 1. Rate Limit Detection
        if (status === 429 || status === 503) {
            this.baseDelay = Math.min(this.baseDelay * 2, 5000);
            return { action: 'pause', delay: this.baseDelay * 2 };
        }

        // 2. WAF Block Detection
        const wafSigns = ['blocked by waf', 'security challenge', 'automated request detected', 'incapsula', 'cloudflare'];
        if (status === 403 && wafSigns.some(s => body.toLowerCase().includes(s))) {
            this.isBlocked = true;
            this.blockCount++;
            return { action: 'mutate', message: 'WAF detected. Rotating headers and payloads.' };
        }

        return { action: 'continue', delay: this.baseDelay };
    }

    getHeaders() {
        // Randomize headers to evade basic signature detection
        const uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Version/17.4 Safari/605.1.15'
        ];
        return {
            'User-Agent': uas[Math.floor(Math.random() * uas.length)],
            'X-Forwarded-For': `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
        };
    }
}

module.exports = new WafDefender();
