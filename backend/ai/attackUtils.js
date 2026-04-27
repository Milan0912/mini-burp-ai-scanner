'use strict';

const { sendRawRequest } = require('../core/repeater');

/**
 * attackUtils.js
 * ==============
 * Shared utilities for sending mutated requests.
 */

async function executeAttack(reqCtx, mutation) {
    try {
        const mutated = mutation ? mutateRequest(reqCtx, mutation.param, mutation.payload, mutation.source) : reqCtx;
        
        const u = new URL(mutated.url.startsWith('h') ? mutated.url : `http://localhost${mutated.url}`);
        const host = u.hostname;
        const port = u.port || (u.protocol === 'https:' ? 443 : 80);
        const useSSL = u.protocol === 'https:';

        const start = Date.now();
        const raw = buildRawRequest(mutated, u);
        
        // Timeout added
        const rawRes = await Promise.race([
            sendRawRequest({ rawRequest: raw, host, port, useSSL, timeoutMs: 30000 }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Engine Timeout')), 30000))
        ]);
        
        const elapsed = Date.now() - start;

        if (!rawRes) return null;

        const hi = rawRes.indexOf(Buffer.from('\r\n\r\n'));
        if (hi === -1) {
            return {
                status: 0,
                body: rawRes.toString('utf8'),
                length: rawRes.length,
                elapsed,
                headers: {},
                redirect: null
            };
        }

        const headPart = rawRes.slice(0, hi).toString('utf8');
        const status = parseInt((headPart.match(/^HTTP\/[\d.]+ (\d+)/) || [0,0])[1]);
        const headers = {};
        headPart.split('\r\n').forEach(l => {
            const i = l.indexOf(':');
            if (i > 0) headers[l.slice(0,i).toLowerCase().trim()] = l.slice(i+1).trim();
        });

        const bodyPart = rawRes.slice(hi + 4).toString('utf8');
        return { status, body: bodyPart, length: Buffer.byteLength(bodyPart), elapsed, headers, redirect: headers['location'] || null };

    } catch (e) { return null; }
}

function mutateRequest(reqCtx, param, payload, source) {
    const cloned = { ...reqCtx, headers: { ...reqCtx.headers } };
    if (source === 'query') {
        const u = new URL(cloned.url.startsWith('h') ? cloned.url : `http://localhost${cloned.url}`);
        u.searchParams.set(param, payload);
        cloned.url = cloned.url.startsWith('h') ? u.href : u.pathname + u.search;
    } else {
        let bodyMap = new URLSearchParams(cloned.body || '');
        bodyMap.set(param, payload);
        cloned.body = bodyMap.toString();
        cloned.headers['content-type'] = 'application/x-www-form-urlencoded';
    }
    return cloned;
}

function buildRawRequest(ctx, u) {
    let raw = `${ctx.method} ${u.pathname}${u.search} HTTP/1.1\r\n`;
    raw += `Host: ${u.host}\r\n`;
    Object.entries(ctx.headers || {}).forEach(([k, v]) => {
        if (!['content-length', 'host', 'connection'].includes(k.toLowerCase())) {
            raw += `${k}: ${v}\r\n`;
        }
    });
    raw += `Connection: close\r\n`;
    if (ctx.body) {
        raw += `Content-Length: ${Buffer.byteLength(ctx.body)}\r\n\r\n${ctx.body}`;
    } else {
        raw += '\r\n';
    }
    return raw;
}

module.exports = { executeAttack, mutateRequest, buildRawRequest };
