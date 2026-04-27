'use strict';

/**
 * Smart Endpoint Manager
 * Tracks scanned targets, endpoints, parameters, and tested vulnerability combinations
 * to prevent duplicate scanning and allow exhaustive coverage.
 */

class EndpointManager {
  constructor() {
    this.history = new Set();
  }

  _hash(url, method, param, vulnType, payload) {
    try {
      const u = new URL(url.startsWith('http') ? url : `http://localhost${url}`);
      const endpoint = `${method}_${u.hostname}${u.pathname}`;
      // Clean payload for consistent hashing
      const pHash = payload ? payload.length.toString() : 'None';
      return `${endpoint}_${param}_${vulnType}_${pHash}`.toLowerCase();
    } catch(e) {
      return `${method}_${url}_${param}_${vulnType}_${payload}`.toLowerCase();
    }
  }

  isTested(url, method, param, vulnType, payload) {
    return this.history.has(this._hash(url, method, param, vulnType, payload));
  }

  markTested(url, method, param, vulnType, payload) {
    this.history.add(this._hash(url, method, param, vulnType, payload));
  }

  clear() {
    this.history.clear();
  }
}

module.exports = new EndpointManager();
