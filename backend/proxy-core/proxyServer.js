'use strict';

/**
 * MiniBurp MITM Proxy Server v4
 *
 * Core fix: Use raw TCP (net.createConnection) for all upstream connections.
 * Response bytes are NEVER parsed by Node's http module, so chunked encoding,
 * Transfer-Encoding headers, Connection: close etc. pass through untouched.
 *
 * Architecture:
 *   HTTP:  parse request → extract host:port → raw TCP tunnel to upstream
 *          → pipe raw responses back (no HTTP parsing of responses)
 *   HTTPS: CONNECT → TLS MITM → same raw TCP tunnel to upstream
 */

const http = require('http');
const https = require('https');
const zlib = require('zlib');
const net  = require('net');
const tls  = require('tls');
const { URL } = require('url');
const { getCertForHost } = require('./caManager');
const { nanoid } = require('nanoid');
const systemState = require('../core/systemState');

const PROXY_PORT_START = 8080;
let interceptorRef = null;
let dbRef = null;
let ioRef = null;
let actualProxyPort = PROXY_PORT_START;

function setInterceptor(i) { interceptorRef = i; }
function setDatabase(d)    { dbRef = d; }
function setIO(io)         { ioRef = io; }
function getProxyPort()    { return actualProxyPort; }

// ── Port probe ─────────────────────────────────────────────────────────────

function findAvailableProxyPort(start) {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(start, '0.0.0.0', () => { const p = srv.address().port; srv.close(() => resolve(p)); });
    srv.on('error', (e) => {
      if (e.code === 'EADDRINUSE') { console.log(`[Proxy] Port ${start} in use → trying ${start + 1}`); resolve(findAvailableProxyPort(start + 1)); }
      else reject(e);
    });
  });
}

// ── Helpers ────────────────────────────────────────────────────────────────

function silentErr(socket) {
  socket.on('error', () => {});
}

function safeWrite(socket, data) {
  try { if (!socket.destroyed && socket.writable) socket.write(data); } catch (_) {}
}

function safeDestroy(socket) {
  try { if (!socket.destroyed) socket.destroy(); } catch (_) {}
}

/** Parse raw HTTP request bytes → object with method, url, headers, body */
function parseRequest(buf) {
  const str = buf.toString('utf8');
  const hi  = str.indexOf('\r\n\r\n');
  if (hi === -1) return null;
  const headerSection = str.slice(0, hi);
  const body = str.slice(hi + 4);
  const lines = headerSection.split('\r\n');
  const [method, urlOrPath, httpVersion = 'HTTP/1.1'] = lines[0].split(' ');
  if (!method || !urlOrPath) return null;
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const ci = lines[i].indexOf(':');
    if (ci > -1) headers[lines[i].slice(0, ci).trim().toLowerCase()] = lines[i].slice(ci + 1).trim();
  }
  return { method, url: urlOrPath, httpVersion, headers, body, raw: buf.toString('utf8') };
}

function buildRawReq(parsed) {
  let r = `${parsed.method} ${parsed.url} ${parsed.httpVersion}\r\n`;
  for (const [k, v] of Object.entries(parsed.headers)) r += `${k}: ${v}\r\n`;
  r += '\r\n';
  if (parsed.body) r += parsed.body;
  return r;
}

function extractTarget(parsed, defaultSsl) {
  try {
    const urlStr = parsed.url.startsWith('http') ? parsed.url : `http://${parsed.headers['host']}${parsed.url}`;
    const u = new URL(urlStr);
    return { host: u.hostname, port: parseInt(u.port) || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search };
  } catch (_) {
    const hostPort = parsed.headers['host'] || 'localhost';
    const h = hostPort.split(':');
    return { host: h[0], port: parseInt(h[1]) || (defaultSsl ? 443 : 80), path: parsed.url };
  }
}

function bad502(clientSocket) {
  safeWrite(clientSocket, 'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBad Gateway');
}

// ── HTTP Response sniffer (taps a raw stream to snapshot status + headers for DB) ──────

/**
 * Wraps an upstream socket read stream. Collects the first 64KB of the
 * response for DB storage without modifying the byte stream at all.
 */
function sniffResponse(chunk, state) {
  if (state.done) return;
  state.buf = Buffer.concat([state.buf, chunk]);
  if (state.buf.length >= 65536) state.done = true;
}

function parseSniffedResponse(buf) {
  const str = buf.toString('utf8', 0, Math.min(buf.length, 65536));
  const hi  = str.indexOf('\r\n\r\n');
  if (hi === -1) return { status: 0, headers: {} };
  const lines = str.slice(0, hi).split('\r\n');
  const status = parseInt((lines[0] || '').split(' ')[1]) || 0;
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const ci = lines[i].indexOf(':');
    if (ci > -1) headers[lines[i].slice(0, ci).trim().toLowerCase()] = lines[i].slice(ci + 1).trim();
  }
  const body = str.slice(hi + 4, 65536);
  return { status, headers, body };
}

function saveToDb({ reqId, parsed, fullUrl, status, resHeaders, resBodyRaw }) {
  if (!dbRef) return;
  console.log(`[Proxy] Analyzing context: ${parsed.method} ${fullUrl} [${status}]`);
  
  const resBody = resBodyRaw ? resBodyRaw.toString('utf8', 0, 50000) : '';

  // Passive Analysis Trigger
  try {
      const PassiveAnalyzer = require('../ai/PassiveAnalyzer');
      PassiveAnalyzer.analyze({
          reqId, method: parsed.method, url: fullUrl, 
          reqHeaders: parsed.headers, reqBody: parsed.body,
          status, resHeaders, resBody 
      });
  } catch (e) {
      console.error('[Proxy] PassiveAnalyzer error:', e);
  }

  try {
    dbRef.saveRequest({
      id: reqId,
      method: parsed.method,
      url: fullUrl,
      status,
      requestHeaders:  JSON.stringify(parsed.headers),
      requestBody:     parsed.body || '',
      responseHeaders: JSON.stringify(resHeaders),
      responseBody:    resBody,
      size:            resBodyRaw ? resBodyRaw.length : 0,
    });
  } catch (e) { console.error('[Proxy] DB save error:', e.message); }
}

// ── Optimized Forwarding: Streaming & Keep-Alive ──────────────────────────

const httpAgent  = new http.Agent({ keepAlive: true, maxSockets: 100 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 100, rejectUnauthorized: false });

/**
 * Modern Stream-based Proxying using Node's http/https modules.
 * This ensures perfect protocol handling, chunked transfer support,
 * and persistent socket reuse via Agents (Keep-Alive).
 */
function smartForward({ clientSocket, parsed, targetHost, targetPort, fullUrl, reqId, useTls }) {
  return new Promise((resolve) => {
    const protocol = useTls ? https : http;
    const agent    = useTls ? httpsAgent : httpAgent;

    // Preserve original headers except proxy-specific ones
    const cleanHeaders = { ...parsed.headers };
    delete cleanHeaders['proxy-connection'];
    delete cleanHeaders['proxy-authorization'];
    
    // We want the upstream to STAY ALIVE if possible
    cleanHeaders['connection'] = 'keep-alive';

    const reqOptions = {
      protocol: useTls ? 'https:' : 'http:',
      hostname: targetHost,
      port: targetPort,
      method: parsed.method,
      path: (useTls || parsed.url.startsWith('http')) ? (extractTarget(parsed, useTls).path || '/') : parsed.url,
      headers: cleanHeaders,
      agent,
      timeout: 30000,
    };

    const sessionManager = require('../core/sessionManager');
    // Pre-process (Cookie injection, rules)
    sessionManager.processRequest(reqOptions);

    const upstreamReq = protocol.request(reqOptions, async (upstreamRes) => {
      // Sync Cookie Jar
      if (upstreamRes.headers['set-cookie']) {
        sessionManager.updateCookies(targetHost, upstreamRes.headers['set-cookie']);
      }

      const isChunked = (upstreamRes.headers['transfer-encoding'] === 'chunked');
      const shouldInterceptRes = interceptorRef?.shouldInterceptResponse(reqId);

      if (shouldInterceptRes && interceptorRef) {
        // ── Response Interception Path (Pause & Edit) ─────────────────────
        const resChunks = [];
        upstreamRes.on('data', c => resChunks.push(c));
        upstreamRes.on('end', async () => {
          const fullBuf = Buffer.concat(resChunks);
          const action = await interceptorRef.handleResponse({
            id: reqId,
            statusCode: upstreamRes.statusCode,
            statusMessage: upstreamRes.statusMessage,
            headers: upstreamRes.headers,
            bodyPreview: fullBuf.toString('utf8', 0, 50000),
            rawResponse: fullBuf.toString('utf8'), // Full raw for editing
            url: fullUrl,
          });

          if (action.type === 'drop') {
            safeDestroy(clientSocket);
            return resolve();
          }

          // Write (possibly edited) response
          if (action.type === 'edit' && action.editedRaw) {
            safeWrite(clientSocket, action.editedRaw);
          } else {
            // Write original
            const statusLine = `HTTP/${upstreamRes.httpVersion} ${upstreamRes.statusCode} ${upstreamRes.statusMessage || ''}\r\n`;
            let hStr = '';
            Object.entries(upstreamRes.headers).forEach(([k, v]) => {
              if (Array.isArray(v)) v.forEach(val => hStr += `${k}: ${val}\r\n`);
              else hStr += `${k}: ${v}\r\n`;
            });
            safeWrite(clientSocket, statusLine + hStr + '\r\n');
            safeWrite(clientSocket, fullBuf);
          }

          // 5. Finalize & Log
          await handlePassiveSniff({ reqId, parsed, fullUrl, upstreamRes, resBodyRaw: fullBuf });
          if (ioRef) ioRef.emit('request:resolved', { id: reqId });
          resolve();
        });
        return;
      }

      // ── Fast Streaming Path (Protocol-Perfect) ─────────────────────────
      const statusLine = `HTTP/${upstreamRes.httpVersion} ${upstreamRes.statusCode} ${upstreamRes.statusMessage || ''}\r\n`;
      let resHeadersRaw = '';
      for (const [k, v] of Object.entries(upstreamRes.headers)) {
        if (Array.isArray(v)) {
          v.forEach(val => resHeadersRaw += `${k}: ${val}\r\n`);
        } else {
          resHeadersRaw += `${k}: ${v}\r\n`;
        }
      }
      safeWrite(clientSocket, statusLine + resHeadersRaw + '\r\n');

      const sniffChunks = [];
      upstreamRes.on('data', (chunk) => {
        sniffChunks.push(chunk);
        if (isChunked) {
          const hexSize = chunk.length.toString(16);
          safeWrite(clientSocket, hexSize + '\r\n');
          safeWrite(clientSocket, chunk);
          safeWrite(clientSocket, '\r\n');
        } else {
          safeWrite(clientSocket, chunk);
        }
      });

      upstreamRes.on('end', async () => {
        if (isChunked) safeWrite(clientSocket, '0\r\n\r\n');
        const resBodyRaw = Buffer.concat(sniffChunks);
        await handlePassiveSniff({ reqId, parsed, fullUrl, upstreamRes, resBodyRaw });
        if (ioRef) ioRef.emit('request:resolved', { id: reqId });
        resolve();
      });
    });

    upstreamReq.on('error', (err) => {
      console.error(`[Proxy] Upstream Error for ${fullUrl}:`, err.message);
      bad502(clientSocket);
      
      // Task 3 FIX: Even on error, save to DB so UI shows the failed request
      saveToDb({
        reqId,
        parsed,
        fullUrl,
        status: 502,
        resHeaders: { 'x-proxy-error': err.message },
        resBodyRaw: Buffer.from(`MiniBurp Proxy Error: ${err.message}`)
      });
      
      resolve();
    });

    upstreamReq.on('timeout', () => {
      upstreamReq.destroy();
      resolve();
    });

    // Write request body if present
    if (parsed.body) {
      upstreamReq.write(parsed.body);
    }
    upstreamReq.end();
  });
}

function handlePassiveSniff({ reqId, parsed, fullUrl, upstreamRes, resBodyRaw }) {
  return new Promise((resolve) => {
    const enc = (upstreamRes.headers['content-encoding'] || '').toLowerCase();
    
    const finish = (finalBody) => {
      saveToDb({
        reqId, parsed, fullUrl,
        status: upstreamRes.statusCode,
        resHeaders: upstreamRes.headers,
        resBodyRaw: finalBody
      });
      resolve();
    };

    if (enc === 'gzip' || enc === 'x-gzip') {
      zlib.gunzip(resBodyRaw, (err, decoded) => finish(err ? resBodyRaw : decoded));
    } else if (enc === 'deflate') {
      zlib.inflate(resBodyRaw, (err, decoded) => finish(err ? resBodyRaw : decoded));
    } else if (enc === 'br') {
      zlib.brotliDecompress(resBodyRaw, (err, decoded) => finish(err ? resBodyRaw : decoded));
    } else {
      finish(resBodyRaw);
    }
  });
}

// ── HTTP keep-alive handler ────────────────────────────────────────────────

function handleClientSocket(clientSocket) {
  console.log('[Proxy] New connection accepted');
  let httpBuf  = Buffer.alloc(0);
  let isTLS    = false;
  let busy     = false;

  silentErr(clientSocket);

  clientSocket.on('data', (chunk) => {
    if (isTLS) return;
    httpBuf = Buffer.concat([httpBuf, chunk]);
    tryProcessOne();
  });

  clientSocket.on('close', () => {});

  async function tryProcessOne() {
    console.log(`[Proxy] tryProcessOne: buffer size ${httpBuf.length}`);
    if (busy) return;

    // Detect CONNECT tunnel (HTTPS)
    const firstLine = httpBuf.toString('ascii', 0, Math.min(httpBuf.length, 8));
    if (firstLine.startsWith('CONNECT')) {
      console.log('[Proxy] CONNECT detected, starting TLS MITM');
      isTLS = true;
      clientSocket.removeAllListeners('data');
      handleConnect(clientSocket, httpBuf);
      return;
    }

    // Wait for complete headers
    const str = httpBuf.toString('utf8');
    const hi  = str.indexOf('\r\n\r\n');
    if (hi === -1) return;

    // Check Content-Length for body
    const clMatch = str.slice(0, hi).match(/content-length:\s*(\d+)/i);
    const cl      = clMatch ? parseInt(clMatch[1]) : 0;
    const need    = hi + 4 + cl;
    if (httpBuf.length < need) return;

    // Slice out one request
    const reqBuf = httpBuf.slice(0, need);
    httpBuf = httpBuf.slice(need);

    busy = true;
    await processHttpRequest(reqBuf);
    busy = false;

    // May have more data buffered (pipelining)
    if (httpBuf.length > 0) tryProcessOne();
  }

  async function processHttpRequest(reqBuf) {
    const parsed = parseRequest(reqBuf);
    if (!parsed) return;

    // ── PAUSED guard — send 503 to browser, crawler traffic still flows ──
    const isCrawler = (parsed.headers['x-miniburp-internal'] === 'crawler');
    if (!systemState.isRunning() && !isCrawler) {
      const body = 'MiniBurp is switching project — please wait.';
      safeWrite(clientSocket,
        `HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
      clientSocket.end();
      return;
    }

    const reqId   = nanoid();
    const { host: targetHost, port: targetPort, path: targetPath } = extractTarget(parsed, false);
    const fullUrl = parsed.url.startsWith('http') ? parsed.url : `http://${parsed.headers['host']}${targetPath}`;

    // Rewrite to relative path for upstream (remove http://host from URL)
    let upstreamBuf = reqBuf;
    if (parsed.url.startsWith('http://') || parsed.url.startsWith('https://')) {
      const relativeParsed = { ...parsed, url: targetPath || '/' };
      // Remove proxy-specific headers
      const cleanHeaders  = { ...relativeParsed.headers };
      delete cleanHeaders['proxy-connection'];
      delete cleanHeaders['proxy-authorization'];
      cleanHeaders['connection'] = 'close';
      relativeParsed.headers = cleanHeaders;
      upstreamBuf = Buffer.from(buildRawReq(relativeParsed));
    }

    // Intercept check
    if (interceptorRef) {
      const action = await interceptorRef.handleRequest({
        id: reqId, method: parsed.method, url: fullUrl,
        headers: parsed.headers, body: parsed.body, raw: parsed.raw, isSsl: false,
      });

      if (action.type === 'drop') {
        safeWrite(clientSocket, 'HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\nDropped');
        return;
      }
      if (action.type === 'edit' && action.editedRaw) {
        upstreamBuf = Buffer.from(action.editedRaw);
      }
    }

    await smartForward({ clientSocket, parsed, targetHost, targetPort, fullUrl, reqId, useTls: false });
  }
}

// ── HTTPS CONNECT handler ──────────────────────────────────────────────────

async function handleConnect(clientSocket, initialBuf) {
  const line = initialBuf.toString('ascii', 0, Math.min(initialBuf.length, 300));
  const m    = line.match(/^CONNECT ([^\s:]+):(\d+) HTTP\//);
  if (!m) { safeDestroy(clientSocket); return; }

  const targetHost = m[1];
  const targetPort = parseInt(m[2]) || 443;

  // Write 200 CE immediately — browser will start sending TLS ClientHello right after
  safeWrite(clientSocket, 'HTTP/1.1 200 Connection Established\r\nProxy-agent: MiniBurp/4.0\r\n\r\n');

  // Pause the socket so the kernel buffers the TLS ClientHello while we load the cert.
  // This prevents data loss during the async await below.
  clientSocket.pause();

  // Load cert for this host (or use cached version)
  let certInfo;
  try {
    certInfo = await getCertForHost(targetHost);
  } catch (e) {
    console.error('[Proxy] Cert error for', targetHost, e.message);
    safeDestroy(clientSocket);
    return;
  }

  // Wrap the paused raw socket in a TLS server socket
  const tlsClient = new tls.TLSSocket(clientSocket, {
    isServer: true,
    cert: certInfo.certPem,
    key:  certInfo.keyPem,
    SNICallback: async (sni, cb) => {
      try {
        const c = await getCertForHost(sni || targetHost);
        cb(null, tls.createSecureContext({ cert: c.certPem, key: c.keyPem }));
      } catch (_) {
        cb(null, tls.createSecureContext({ cert: certInfo.certPem, key: certInfo.keyPem }));
      }
    },
  });
  tlsClient.on('error', (e) => {
    if (e.code !== 'ECONNRESET' && e.code !== 'EPIPE')
      console.error('[TLS MITM] Error for', targetHost, ':', e.code, e.message);
  });

  // Resume now — buffered ClientHello bytes flow into the TLS engine
  clientSocket.resume();

  let tlsBuf = Buffer.alloc(0);
  let busy   = false;

  tlsClient.on('data', (chunk) => {
    tlsBuf = Buffer.concat([tlsBuf, chunk]);
    tryProcessTls();
  });

  tlsClient.on('close', () => {});
  tlsClient.on('end',   () => {});

  async function tryProcessTls() {
    if (busy) return;

    const str = tlsBuf.toString('utf8');
    const hi  = str.indexOf('\r\n\r\n');
    if (hi === -1) return;

    const clMatch = str.slice(0, hi).match(/content-length:\s*(\d+)/i);
    const cl      = clMatch ? parseInt(clMatch[1]) : 0;
    const need    = hi + 4 + cl;
    if (tlsBuf.length < need) return;

    const reqBuf = tlsBuf.slice(0, need);
    tlsBuf = tlsBuf.slice(need);

    busy = true;
    await processTlsRequest(reqBuf);
    busy = false;

    if (tlsBuf.length > 0) tryProcessTls();
  }

  async function processTlsRequest(reqBuf) {
    const parsed = parseRequest(reqBuf);
    if (!parsed) return;

    const reqId   = nanoid();
    const { path: targetPath } = extractTarget(parsed, true);
    const fullUrl = `https://${targetHost}${targetPath}`;

    // Clean headers for upstream
    const cleanHeaders = { ...parsed.headers };
    delete cleanHeaders['proxy-connection'];
    delete cleanHeaders['proxy-authorization'];
    cleanHeaders['connection'] = 'close';

    let upstreamBuf = Buffer.from(buildRawReq({ ...parsed, url: targetPath || '/', headers: cleanHeaders }));

    // Intercept check
    if (interceptorRef) {
      const action = await interceptorRef.handleRequest({
        id: reqId, method: parsed.method, url: fullUrl,
        headers: parsed.headers, body: parsed.body, raw: parsed.raw,
        isSsl: true, targetHost, targetPort,
      });

      if (action.type === 'drop') return;
      if (action.type === 'edit' && action.editedRaw) {
        upstreamBuf = Buffer.from(action.editedRaw);
      }
    }

    // Forward via smartForward to upstream (HTTP agent reuse)
    await smartForward({ clientSocket: tlsClient, parsed, targetHost, targetPort, fullUrl, reqId, useTls: true });
  }
}

// ── Start ──────────────────────────────────────────────────────────────────

async function startProxy() {
  const PROXY_PORT = await findAvailableProxyPort(PROXY_PORT_START);
  if (PROXY_PORT !== PROXY_PORT_START)
    console.log(`[Proxy] Port ${PROXY_PORT_START} in use → switched to ${PROXY_PORT}`);
  actualProxyPort = PROXY_PORT;

  const server = net.createServer((socket) => {
    socket.on('error', () => {});
    handleClientSocket(socket);
  });

  server.listen(PROXY_PORT, '0.0.0.0', () =>
    console.log(`[Proxy] MITM Proxy listening on port ${PROXY_PORT}`)
  );
  server.on('error', (e) => console.error('[Proxy] Server error:', e.message));
  return server;
}

module.exports = { startProxy, setInterceptor, setDatabase, setIO, getProxyPort };
