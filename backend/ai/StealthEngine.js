'use strict';

/**
 * Stealth Engine — Evasion & Anonymization
 * ========================================
 * Features:
 * 1. Random Delays (500ms - 2500ms)
 * 2. Header Randomization (User-Agent rotation)
 * 3. Jitter (Slight modification of non-essential headers)
 */

class StealthEngine {
  constructor() {
    this.userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
    ];
  }

  /**
   * Apply stealth modifications to a request.
   */
  async apply(request) {
    // 1. Random Delay
    const delay = this.getDelay();
    if (delay > 0) {
       await new Promise(resolve => setTimeout(resolve, delay));
    }

    // 2. Advanced Header Rotation (Task 6)
    if (request.headers) {
      const ua = this.userAgents[Math.floor(Math.random() * this.userAgents.length)];
      request.headers['User-Agent'] = ua;

      // Rotate Referer to appear like organic traffic
      const referers = ['https://www.google.com/', 'https://duckduckgo.com/', 'https://www.bing.com/', ''];
      const ref = referers[Math.floor(Math.random() * referers.length)];
      if (ref) request.headers['Referer'] = ref;

      // Add common browser headers to bypass simple WAF checks
      request.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
      request.headers['Accept-Language'] = 'en-US,en;q=0.9';
      request.headers['Cache-Control'] = 'no-cache';
      request.headers['Pragma'] = 'no-cache';
      
      // Jitter: Add occasional non-essential headers
      if (Math.random() > 0.7) request.headers['X-Requested-With'] = 'XMLHttpRequest';
      if (Math.random() > 0.8) request.headers['DNT'] = '1';
      if (Math.random() > 0.9) request.headers['Sec-GPC'] = '1';
    }

    return request;
  }

  /**
   * getDelay: Returns a jitter delay value in ms.
   */
  getDelay() {
     return Math.floor(Math.random() * (2500 - 500 + 1)) + 500;
  }
}

module.exports = StealthEngine;
