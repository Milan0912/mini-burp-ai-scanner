'use strict';

/**
 * Interceptor v4 — Single-intercept queue system (Burp-style)
 *
 * Key behaviors:
 * 1. Only ONE request shown to user at a time
 * 2. Smart filter: auto-forward CSS, JS, images, fonts, favicons
 * 3. Interceptable requests (HTML, API, JSON) queue server-side
 * 4. As user Forwards/Drops, next queued request is shown
 * 5. Per-request response intercept (scheduleResponseIntercept)
 */

const { nanoid } = require('nanoid');
const EventEmitter = require('events');

const AUTO_FORWARD_TIMEOUT_MS = 120000; // 2 min safety

// URL extensions and MIME types to auto-forward without interception
const SKIP_EXTENSIONS = /\.(css|js|mjs|jsx|ts|tsx|map|png|jpg|jpeg|gif|webp|avif|svg|ico|bmp|woff|woff2|ttf|eot|otf|mp4|mp3|wav|ogg|flac|pdf|zip|tar|gz|wasm)(\?[^?]*)?$/i;

const SKIP_ACCEPT = [
  'text/css',
  'image/',
  'font/',
  'application/javascript',
  'application/x-javascript',
  'text/javascript',
];

const SKIP_CONTENT_TYPE = [
  'application/javascript',
  'text/javascript',
  'text/css',
  'image/',
  'font/',
];

/**
 * Decide whether this request should be intercepted.
 * Returns true for HTML pages, JSON APIs, form submissions.
 * Returns false for static assets.
 */
function isInterceptable(ctx) {
  const rawUrl = (ctx.url || '').split('?')[0];
  const accept = (ctx.headers?.accept || '').toLowerCase();
  const ct = (ctx.headers?.['content-type'] || '').toLowerCase();

  // Skip by file extension
  if (SKIP_EXTENSIONS.test(rawUrl)) return false;

  // Skip by Accept header (browser requesting static resource)
  for (const pattern of SKIP_ACCEPT) {
    if (accept.includes(pattern)) return false;
  }

  // Skip by Content-Type (server-sent static)
  for (const pattern of SKIP_CONTENT_TYPE) {
    if (ct.includes(pattern)) return false;
  }

  // Skip WebSocket upgrades
  if ((ctx.headers?.upgrade || '').toLowerCase() === 'websocket') return false;

  // CONNECT requests (tunnels) — always forward, TLS layer handles intercept
  if (ctx.method === 'CONNECT') return false;

  return true;
}

class Interceptor extends EventEmitter {
  constructor() {
    super();
    this.interceptOn = false;
    this.interceptOnlyInScope = false;
    this.scope = []; // Array of strings or regexes

    // Single-intercept queue: only ONE request shown at a time
    this.activeRequest = null;     // { ctx, resolve, timer } — currently shown request
    this.waitQueue    = [];        // [{ ctx, resolve }] — waiting to be shown

    // Per-request response intercept
    this.scheduledResponseIntercepts = new Set();
    this.pendingResponses = new Map();

    this.io = null;
  }

  setIO(io) {
    this.io = io;
    this._bindSocketActions();
  }

  isInScope(url = '') {
    if (this.scope.length === 0) return true; // Default
    return this.scope.some(s => {
      if (s instanceof RegExp) return s.test(url);
      return url.includes(s);
    });
  }

  _bindSocketActions() {
    if (!this.io) return;

    this.io.on('connection', (socket) => {
      socket.emit('intercept:state', { 
         on: this.interceptOn, 
         onlyInScope: this.interceptOnlyInScope, 
         scope: this.scope.map(s => s instanceof RegExp ? s.source : s) 
      });
      socket.emit('queue:count', { count: this.waitQueue.length });

      // ── Scope actions ──────────────────────────────────────────
      socket.on('scope:set', ({ scope, onlyInScope }) => {
        this.scope = (scope || []).map(s => {
           try { if (s.startsWith('/') && s.endsWith('/')) return new RegExp(s.slice(1, -1), 'i'); } catch {}
           return s;
        });
        this.interceptOnlyInScope = !!onlyInScope;
        this.io.emit('intercept:state', { 
           on: this.interceptOn, 
           onlyInScope: this.interceptOnlyInScope, 
           scope: this.scope.map(s => s instanceof RegExp ? s.source : s) 
        });
        console.log(`[Scope] Updated scope: ${this.scope.length} patterns, OnlyInScope: ${this.interceptOnlyInScope}`);
      });

      // ── Request actions ──────────────────────────────────────────
      socket.on('action:forward', ({ id, editedRaw }) => {
        this._resolveActive(id, { type: editedRaw ? 'edit' : 'forward', editedRaw });
      });

      socket.on('action:drop', ({ id }) => {
        this._resolveActive(id, { type: 'drop' });
      });

      socket.on('action:edit', ({ id, editedRaw }) => {
        this._resolveActive(id, { type: 'edit', editedRaw });
      });

      // ── Per-request response intercept ───────────────────────────
      socket.on('action:intercept-response', ({ id }) => {
        this.scheduledResponseIntercepts.add(id);
      });

      // ── Response actions ─────────────────────────────────────────
      socket.on('response:forward', ({ id, editedRaw }) => {
        this._resolveResponse(id, { type: editedRaw ? 'edit' : 'forward', editedRaw });
      });

      socket.on('response:drop', ({ id }) => {
        this._resolveResponse(id, { type: 'drop' });
      });

      // ── Intercept toggle ─────────────────────────────────────────
      socket.on('intercept:set', ({ on }) => {
        this.interceptOn = !!on;
        if (!on) {
          // Auto-forward everything in queue and active request
          this._flushAll();
        }
        this.io.emit('intercept:state', { on: this.interceptOn });
      });
    });
  }

  // ── Active request management ────────────────────────────────────

  _resolveActive(id, action) {
    if (!this.activeRequest || this.activeRequest.ctx.id !== id) {
      // May be a queued request that was already resolved or wrong id
      return;
    }
    const { resolve, timer } = this.activeRequest;
    clearTimeout(timer);
    this.activeRequest = null;
    resolve(action);
    if (this.io) this.io.emit('request:resolved', { id, action: action.type });

    // Process next in queue
    this._processNextInQueue();
  }

  _processNextInQueue() {
    if (this.waitQueue.length === 0) {
      if (this.io) this.io.emit('queue:count', { count: 0 });
      return;
    }

    const next = this.waitQueue.shift();
    if (this.io) this.io.emit('queue:count', { count: this.waitQueue.length });

    this._holdRequest(next.ctx, next.resolve);
  }

  _holdRequest(ctx, resolve) {
    const timer = setTimeout(() => {
      console.warn('[Interceptor] Auto-forwarding timed-out request:', ctx.id);
      if (this.activeRequest?.ctx.id === ctx.id) {
        this._resolveActive(ctx.id, { type: 'forward' });
      }
    }, AUTO_FORWARD_TIMEOUT_MS);

    this.activeRequest = { ctx, resolve, timer };

    if (this.io) {
      this.io.emit('request:intercepted', {
        id: ctx.id,
        method: ctx.method,
        url: ctx.url,
        headers: ctx.headers,
        body: ctx.body || '',
        raw: ctx.raw || '',
        isSsl: ctx.isSsl || false,
        timestamp: new Date().toISOString(),
      });
    } else {
      // No UI — just forward
      clearTimeout(timer);
      this.activeRequest = null;
      resolve({ type: 'forward' });
    }
  }

  _flushAll() {
    // Forward active
    if (this.activeRequest) {
      const { ctx, resolve, timer } = this.activeRequest;
      clearTimeout(timer);
      this.activeRequest = null;
      resolve({ type: 'forward' });
      if (this.io) this.io.emit('request:resolved', { id: ctx.id, action: 'forward' });
    }
    // Forward all queued
    for (const { ctx, resolve } of this.waitQueue) {
      resolve({ type: 'forward' });
      if (this.io) this.io.emit('request:resolved', { id: ctx.id, action: 'forward' });
    }
    this.waitQueue = [];
    if (this.io) {
      this.io.emit('queue:count', { count: 0 });
    }
  }

  // ── handleRequest ────────────────────────────────────────────────

  async handleRequest(ctx) {
    if (!ctx.id) ctx.id = nanoid();

    try {
      const { requestAnalyzer } = require('../ai/requestAnalyzer');
      await requestAnalyzer(ctx);
    } catch (_) {}

    // Auto-forward when intercept is off
    if (!this.interceptOn) return { type: 'forward' };

    // Scope check
    if (this.interceptOnlyInScope && !this.isInScope(ctx.url)) {
      return { type: 'forward' };
    }

    // Bypassing intercept queue in AUTO mode for autonomous testing
    const agentEngine = require('../ai/agentEngine');
    if (agentEngine.mode === 'Auto') {
       return { type: 'forward' };
    }

    // Smart bypass for Autonomous Scanner (AI Engine has already captured baseline above)
    if (ctx.headers && ctx.headers['x-miniburp-internal'] === 'crawler') {
       return { type: 'forward' };
    }

    // Smart filter: auto-forward static resources even when intercept ON
    if (!isInterceptable(ctx)) return { type: 'forward' };

    // Interceptable request — queue or hold
    return new Promise((resolve) => {
      if (this.activeRequest) {
        // One already being shown — queue this one
        this.waitQueue.push({ ctx, resolve });
        if (this.io) this.io.emit('queue:count', { count: this.waitQueue.length });
        console.log(`[Interceptor] Queued: ${ctx.method} ${ctx.url} (${this.waitQueue.length} in queue)`);
      } else {
        // Nothing active — show immediately
        this._holdRequest(ctx, resolve);
      }
    });
  }

  // ── Response intercept ────────────────────────────────────────────

  shouldInterceptResponse(reqId) {
    return this.scheduledResponseIntercepts.has(reqId);
  }

  _resolveResponse(id, action) {
    const pending = this.pendingResponses.get(id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pendingResponses.delete(id);
    this.scheduledResponseIntercepts.delete(id);
    pending.resolve(action);
    if (this.io) this.io.emit('response:resolved', { id, action: action.type });
  }

  async handleResponse(ctx) {
    if (!ctx.id) ctx.id = nanoid();

    try {
      const { responseAnalyzer } = require('../ai/responseAnalyzer');
      await responseAnalyzer(ctx);
    } catch (_) {}

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        console.warn('[Interceptor] Auto-forwarding timed-out response:', ctx.id);
        this._resolveResponse(ctx.id, { type: 'forward' });
      }, AUTO_FORWARD_TIMEOUT_MS);

      this.pendingResponses.set(ctx.id, { resolve, timer });

      if (this.io) {
        this.io.emit('response:intercepted', {
          id: ctx.id,
          statusCode: ctx.statusCode,
          statusMessage: ctx.statusMessage,
          headers: ctx.headers,
          bodyPreview: ctx.bodyPreview || '',
          rawResponse: ctx.rawResponse || '',
          url: ctx.url || '',
          timestamp: new Date().toISOString(),
        });
      } else {
        clearTimeout(timer);
        this.pendingResponses.delete(ctx.id);
        resolve({ type: 'forward' });
      }
    });
  }

  getStatus() {
    const queue = [];
    if (this.activeRequest?.ctx) {
      const ctx = this.activeRequest.ctx;
      queue.push({
        id: ctx.id,
        method: ctx.method,
        url: ctx.url,
        headers: ctx.headers || {},
        body: ctx.body || '',
        raw: ctx.raw || '',
        isSsl: ctx.isSsl || false,
        timestamp: ctx.timestamp || new Date().toISOString(),
      });
    }
    for (const item of this.waitQueue) {
      const ctx = item.ctx;
      queue.push({
        id: ctx.id,
        method: ctx.method,
        url: ctx.url,
        headers: ctx.headers || {},
        body: ctx.body || '',
        raw: ctx.raw || '',
        isSsl: ctx.isSsl || false,
        timestamp: ctx.timestamp || new Date().toISOString(),
      });
    }
    return {
      interceptOn: this.interceptOn,
      queue,
      queueLength: queue.length,
      scheduledResponseIntercepts: this.scheduledResponseIntercepts.size,
      pendingResponseCount: this.pendingResponses.size,
    };
  }
}

module.exports = new Interceptor();
