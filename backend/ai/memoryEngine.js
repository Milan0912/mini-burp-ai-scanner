'use strict';

/**
 * MemoryEngine.js
 * ===============
 * Stores successful and failed payloads per endpoint pattern.
 * Enables the "Learn" phase of the Orchestrator loop.
 */

const successfulPayloads = new Map(); // key: pattern, value: Set of payloads
const failedPayloads = new Map();     // key: pattern, value: Set of payloads

function getPattern(method, url, param) {
    try {
        const u = new URL(url);
        return `${method}|${u.hostname}${u.pathname}|${param}`;
    } catch {
        return `${method}|${url}|${param}`;
    }
}

function storeResult(method, url, param, type, payload, success) {
    const key = `${getPattern(method, url, param)}|${type}`;
    if (success) {
        if (!successfulPayloads.has(key)) successfulPayloads.set(key, new Set());
        successfulPayloads.get(key).add(payload);
    } else {
        if (!failedPayloads.has(key)) failedPayloads.set(key, new Set());
        failedPayloads.get(key).add(payload);
    }
}

function getBestPayloads(method, url, param, type) {
    const key = `${getPattern(method, url, param)}|${type}`;
    return Array.from(successfulPayloads.get(key) || []);
}

function isBlacklisted(method, url, param, type, payload) {
    const key = `${getPattern(method, url, param)}|${type}`;
    return (failedPayloads.get(key) || new Set()).has(payload);
}

module.exports = { storeResult, getBestPayloads, isBlacklisted };
