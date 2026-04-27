'use strict';

/**
 * Intruder — automated attack engine.
 * Sends multiple requests with payload substitution at §marker§ positions.
 */

const { sendRawRequest } = require('./repeater');

let running = false;
let abortFlag = false;

/**
 * Run an intruder attack.
 * @param {Object} opts
 * @param {string}   opts.rawRequest - Raw HTTP request template (use §value§ for payload positions)
 * @param {string}   opts.host
 * @param {number}   opts.port
 * @param {boolean}  opts.useSSL
 * @param {string[]} opts.payloads  - Array of payload strings
 * @param {string}   opts.attackType - 'sniper' (multiple positions, one payload at a time)
 * @param {Object}   opts.io - Socket.IO instance for real-time results
 */
async function runIntruder({ rawRequest, host, port, useSSL, payloads, attackType = 'sniper', io, grepRegex }) {
  if (running) {
    console.warn('[Intruder] Already running, stop first');
    return;
  }

  const grepObj = grepRegex ? (typeof grepRegex === 'string' ? new RegExp(grepRegex, 'i') : grepRegex) : null;
  running = true;
  abortFlag = false;

  const targetPort = port ? parseInt(port) : (useSSL ? 443 : 80);

  // Find all §...§ positions in the raw request
  const positionRegex = /§([^§]*)§/g;
  const positions = [];
  let m;
  while ((m = positionRegex.exec(rawRequest)) !== null) {
    positions.push({ index: m.index, original: m[0], value: m[1] });
  }

  if (positions.length === 0) {
    positions.push({ index: -1, original: null, value: '' });
  }

  let idx = 0;
  const totalRequests = attackType === 'sniper' ? positions.length * payloads.length : payloads.length;
  if (io) io.emit('intruder:started', { total: totalRequests, positions: positions.length });

  const executeAttack = async (currentInjected, currentPayload) => {
    if (abortFlag) return false;
    const start = Date.now();
    let status = 0, length = 0, error = null, responsePreview = '', grepMatch = null;
    
    try {
      const response = await sendRawRequest({
        rawRequest: currentInjected,
        host,
        port: targetPort,
        useSSL: !!useSSL,
        timeoutMs: 10000,
      });

      const resStr = response.toString('utf8');

      if (grepObj) {
        const m = resStr.match(grepObj);
        grepMatch = m ? m[0] : null;
      }

      const statusMatch = resStr.match(/^HTTP\/[\d.]+ (\d+)/);
      status = statusMatch ? parseInt(statusMatch[1]) : 0;
      length = response.length;
      responsePreview = resStr.slice(0, 500);
    } catch (e) { error = e.message; }

    if (io) {
      io.emit('intruder:result', {
        index: idx, payload: currentPayload, status, length, elapsed: Date.now() - start, error, responsePreview, grepMatch
      });
    }
    idx++;
    await sleep(50);
    return true;
  };

  if (attackType === 'sniper') {
    for (const pos of positions) {
      for (const p of payloads) {
        if (abortFlag) break;
        // Slice-based replace for single position only
        const injected = rawRequest.slice(0, pos.index) + p + rawRequest.slice(pos.index + (pos.original ? pos.original.length : 0));
        await executeAttack(injected, p);
      }
    }
  } else {
    // Battering Ram / Single-loop patterns
    for (const p of payloads) {
      if (abortFlag) break;
      const injected = rawRequest.replace(/§([^§]*)§/g, p);
      await executeAttack(injected, p);
    }
  }

  running = false;
  abortFlag = false;
  if (io) io.emit('intruder:finished', { total: idx });
  console.log(`[Intruder] Finished — sent ${idx} requests`);
}

function stopIntruder() {
  abortFlag = true;
  running = false;
  console.log('[Intruder] Stopped by user');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { runIntruder, stopIntruder };
