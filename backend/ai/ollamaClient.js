'use strict';

/**
 * MiniBurp Ollama AI Client v3
 * =============================
 * Unified interface for all AI calls in the system.
 * 
 * Architecture:
 *   generateAIResponse(prompt, options) → string | null
 *   All other functions build on top of this.
 * 
 * Resilience:
 *   - Auto-detects available models (prefers mistral > llama3 > first available)
 *   - If model missing → pulls it automatically once
 *   - If Ollama offline → returns null, callers use heuristic fallback
 *   - Strict timeouts to never block the proxy engine
 */

const http = require('http');
const axios = require('axios');

const OLLAMA_BASE = 'http://localhost:11434';
const PREFERRED_MODELS = ['mistral', 'llama3', 'llama3.2', 'qwen2.5-coder', 'phi3'];
const DEFAULT_TIMEOUT_MS = 30000;

// ── Internal state ──────────────────────────────────────────────────────────
let _activeModel = null;          // resolved model name (cached after first probe)
let _ollamaOnline = null;         // null = not yet checked
let _pullInProgress = new Set();  // models currently being pulled

// ── 1. Connectivity & Model Discovery ───────────────────────────────────────

/**
 * Check if Ollama is reachable and return list of installed model names.
 * Returns [] if offline (never throws).
 */
async function getInstalledModels() {
    try {
        const res = await axios.get(`${OLLAMA_BASE}/api/tags`, { timeout: 3000 });
        const models = (res.data && res.data.models) || [];
        return models.map(m => m.name.split(':')[0]); // strip ':latest' tag
    } catch {
        return null; // null = offline
    }
}

/**
 * Resolve the best available model. Caches result.
 * Priority: PREFERRED_MODELS order → first installed model → pull mistral.
 */
async function resolveModel() {
    if (_activeModel) return _activeModel;

    const installed = await getInstalledModels();

    if (installed === null) {
        _ollamaOnline = false;
        console.warn('[OllamaClient] Ollama is OFFLINE. AI features will use heuristic fallback.');
        return null;
    }

    _ollamaOnline = true;
    console.log(`[OllamaClient] Ollama online. Installed models: [${installed.join(', ') || 'none'}]`);

    // Pick best preferred model that is installed
    for (const preferred of PREFERRED_MODELS) {
        if (installed.some(m => m.startsWith(preferred))) {
            _activeModel = preferred;
            console.log(`[OllamaClient] Using model: ${_activeModel}`);
            return _activeModel;
        }
    }

    // Use first available model if none preferred
    if (installed.length > 0) {
        _activeModel = installed[0];
        console.log(`[OllamaClient] Using first available model: ${_activeModel}`);
        return _activeModel;
    }

    // No models → auto-pull mistral (non-blocking, fire-and-forget)
    if (!_pullInProgress.has('mistral')) {
        _pullInProgress.add('mistral');
        console.log('[OllamaClient] No models found. Pulling mistral in background...');
        pullModel('mistral').then(() => {
            _activeModel = 'mistral';
            _pullInProgress.delete('mistral');
            console.log('[OllamaClient] mistral pull complete. AI now available.');
        }).catch(e => {
            _pullInProgress.delete('mistral');
            console.warn('[OllamaClient] Failed to pull mistral:', e.message);
        });
    }

    return null; // not ready yet
}

/**
 * Pull a model from Ollama registry (streaming pull).
 */
async function pullModel(modelName) {
    await axios.post(`${OLLAMA_BASE}/api/pull`, { name: modelName, stream: false }, { timeout: 600000 });
}

// ── 2. Core Generation Function ──────────────────────────────────────────────

/**
 * PRIMARY ENTRY POINT — generateAIResponse(prompt, options?)
 * 
 * @param {string} prompt - The full prompt to send
 * @param {object} options
 *   @param {string}  options.system    - Optional system prompt
 *   @param {boolean} options.json      - If true, parse response as JSON (default false)
 *   @param {number}  options.timeout   - Timeout in ms (default 30000)
 *   @param {string}  options.model     - Override model name
 * @returns {string|object|null} - AI response string, parsed JSON, or null on failure
 */
async function generateAIResponse(prompt, options = {}) {
    const {
        system = '',
        json = false,
        timeout = DEFAULT_TIMEOUT_MS,
        model: modelOverride = null
    } = options;

    const model = modelOverride || await resolveModel();

    if (!model) {
        // Ollama offline or model not ready
        return null;
    }

    try {
        const payload = {
            model,
            prompt,
            stream: false,
            ...(system && { system }),
            ...(json && { format: 'json' })
        };

        const response = await axios.post(
            `${OLLAMA_BASE}/api/generate`,
            payload,
            { timeout }
        );

        if (!response.data || !response.data.response) return null;

        let rawText = response.data.response.trim();

        if (json) {
            // Strip markdown code fences if present
            rawText = rawText
                .replace(/^```json\s*/i, '')
                .replace(/^```\s*/i, '')
                .replace(/\s*```$/i, '')
                .trim();
            try {
                return JSON.parse(rawText);
            } catch {
                // Try to extract JSON object/array from text
                const match = rawText.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
                if (match) {
                    try { return JSON.parse(match[1]); } catch { return null; }
                }
                return null;
            }
        }

        return rawText;

    } catch (err) {
        if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
            _ollamaOnline = false;
            _activeModel = null; // Reset so next call re-probes
        }
        console.warn(`[OllamaClient] Request failed (${model}): ${err.message}`);
        return null;
    }
}

// ── 3. Domain-Specific Helpers (all use generateAIResponse internally) ───────

/**
 * Decide attack strategy for an endpoint.
 * Returns structured JSON or heuristic fallback.
 */
async function decideStrategy(context) {
    const prompt = `
You are an elite bug bounty hunter analyzing a web endpoint.

URL: ${context.url}
Method: ${context.method}
Parameters: ${JSON.stringify(context.params || {})}
Content-Type: ${context.contentType || 'unknown'}
Page Sample: ${(context.pageContentSnippet || '').slice(0, 400)}

Identify the endpoint type and choose the best attack vectors.

Rules:
- login page → prioritize SQL Auth Bypass
- search/query params → prioritize XSS
- id/uid numeric params → prioritize SQLi Boolean + IDOR
- file/path params → prioritize LFI
- admin/dashboard → prioritize IDOR + privilege escalation

Output ONLY valid JSON:
{
  "endpoint_type": "login|search|profile|api|admin|generic",
  "attack_plan": ["vector1", "vector2"],
  "priority": "high|medium|low",
  "reasoning": "brief technical reason",
  "initial_payloads": [{"vector": "sqli", "payload": "payload_here"}]
}`;

    const result = await generateAIResponse(prompt, { json: true, timeout: 20000 });

    // Heuristic fallback
    return result || _heuristicStrategy(context);
}

/**
 * Analyze an attack result and decide next action.
 */
async function analyzeAttackResult(data) {
    const prompt = `
You are a penetration tester analyzing an attack result. Be concise, no theory.

URL: ${data.url}
Payload: ${data.payload}
Baseline → Status: ${data.baseline.status}, Length: ${data.baseline.length}
Attack   → Status: ${data.test.status}, Length: ${data.test.length}, Redirect: ${data.test.redirect || 'none'}, Time: ${data.test.elapsed}ms

Detection rules:
1. Status 302 to non-login page after auth payload → SQL Auth Bypass (CRITICAL)
2. Response length diff > 200 bytes → possible injection
3. Payload reflected verbatim → XSS
4. Response time > 4000ms with sleep payload → Blind SQLi
5. No signal → reject

Output ONLY valid JSON:
{
  "is_vulnerable": true,
  "type": "sqli|xss|idor|lfi|none",
  "confidence": 0-100,
  "reason": "technical reason",
  "next_action": "continue|change_vector|exploit",
  "next_payloads": []
}`;

    const result = await generateAIResponse(prompt, { json: true, timeout: 20000 });
    return result || { is_vulnerable: false, confidence: 0, next_action: 'continue' };
}

/**
 * Generate next adaptive attack strategy after failure.
 */
async function nextStrategy(context) {
    const prompt = `
You are an adaptive exploit engineer. Previous payloads failed.

Failed vectors: ${JSON.stringify(context.failed_vectors || [])}
Previous attempts: ${JSON.stringify((context.previous_attempts || []).slice(-5))}
Patterns observed: ${context.response_patterns || 'none'}

Suggest alternative attack approach.

Output ONLY valid JSON:
{
  "next_vector": "vector_name",
  "new_payloads": ["payload1", "payload2", "payload3"],
  "strategy": "brief reasoning"
}`;

    const result = await generateAIResponse(prompt, { json: true, timeout: 15000 });
    return result || _heuristicNextStrategy(context);
}

/**
 * Analyze a proxy-intercepted request and suggest vulnerabilities.
 */
async function analyzeProxyRequest(ctx) {
    let params = {};
    try {
        const urlObj = new URL(ctx.url);
        params = Object.fromEntries(urlObj.searchParams);
    } catch {}

    const prompt = `
Analyze this intercepted HTTP request for security vulnerabilities.
URL: ${ctx.url}
Method: ${ctx.method}
Body: ${(ctx.body || '').slice(0, 300)}
Params: ${JSON.stringify(params)}

Output ONLY valid JSON:
{
  "risky_parameters": ["param1"],
  "possible_vulnerabilities": ["SQLi", "XSS"],
  "payload_suggestions": [{"param": "id", "payload": "1' OR 1=1--"}],
  "reasoning": "brief explanation"
}`;

    const result = await generateAIResponse(prompt, {
        system: 'You are a passive security analyzer for a bug bounty proxy. Do NOT attack, only analyze.',
        json: true,
        timeout: 15000
    });
    return result;
}

/**
 * Generate a professional bug bounty report for a confirmed finding.
 */
async function generateReportDetails(finding) {
    const prompt = `Write a concise professional bug bounty report for this verified vulnerability: ${JSON.stringify(finding)}`;
    return await generateAIResponse(prompt, { timeout: 20000 });
}

// ── 4. Heuristic Fallbacks ────────────────────────────────────────────────────
// Used when AI is unavailable — ensure system always functions.

function _heuristicStrategy(context) {
    const url = (context.url || '').toLowerCase();
    const params = Object.keys(context.params || {}).map(k => k.toLowerCase());

    let endpoint_type = 'generic';
    let attack_plan = ['sqli', 'xss'];
    let priority = 'medium';

    if (/login|signin|auth|session/.test(url) || params.some(p => /user|pass|pwd/.test(p))) {
        endpoint_type = 'login';
        attack_plan = ['sqli_auth', 'sqli'];
        priority = 'high';
    } else if (params.some(p => /^(id|uid|user_id|item|cat|product)$/.test(p))) {
        endpoint_type = 'profile';
        attack_plan = ['sqli', 'idor'];
        priority = 'high';
    } else if (params.some(p => /search|q|query|find/.test(p))) {
        endpoint_type = 'search';
        attack_plan = ['xss', 'sqli'];
        priority = 'medium';
    } else if (params.some(p => /file|path|dir|include/.test(p))) {
        endpoint_type = 'file';
        attack_plan = ['lfi'];
        priority = 'high';
    } else if (/admin|dashboard|panel/.test(url)) {
        endpoint_type = 'admin';
        attack_plan = ['idor', 'sqli'];
        priority = 'high';
    }

    return { endpoint_type, attack_plan, priority, reasoning: 'heuristic (AI offline)', initial_payloads: [] };
}

function _heuristicNextStrategy(context) {
    const failed = context.failed_vectors || [];
    const allVectors = ['sqli', 'xss', 'lfi', 'idor', 'sqli_auth'];
    const next = allVectors.find(v => !failed.includes(v)) || 'xss';
    return {
        next_vector: next,
        new_payloads: ["' OR 1=1--", '"><script>alert(1)</script>', '../../../etc/passwd'],
        strategy: 'heuristic rotation (AI offline)'
    };
}

// ── 5. Status & Utilities ─────────────────────────────────────────────────────

async function getStatus() {
    const installed = await getInstalledModels();
    return {
        online: installed !== null,
        activeModel: _activeModel,
        installedModels: installed || [],
        ollamaUrl: OLLAMA_BASE
    };
}

// Reset cached model so next call re-probes (useful after ollama restart)
function resetCache() {
    _activeModel = null;
    _ollamaOnline = null;
}

// ── 6. Legacy compatibility shims ────────────────────────────────────────────
// Keep old function names working so existing imports don't break.

async function streamOllama(prompt, timeoutMs = DEFAULT_TIMEOUT_MS) {
    return await generateAIResponse(prompt, { timeout: timeoutMs });
}

async function generatePayloads(type, paramName, paramValue) {
    const prompt = `Generate exactly 5 attack payloads for testing ${type} on parameter '${paramName}' with original value '${paramValue}'. Output ONLY a JSON array of 5 strings. No explanation.`;
    const result = await generateAIResponse(prompt, { timeout: 10000 });
    if (!result) return null;
    const match = result.match(/\[[\s\S]*\]/);
    if (match) {
        try {
            const arr = JSON.parse(match[0]);
            if (Array.isArray(arr) && arr.length > 0) return arr;
        } catch {}
    }
    return null;
}

async function analyzeResponse(type, payload, diffPercentage) {
    const prompt = `A ${type} attack using payload "${payload}" caused a ${Math.round(diffPercentage * 100)}% response change. In one sentence, explain what this means technically. NO markdown.`;
    const result = await generateAIResponse(prompt, { timeout: 10000 });
    return result || `${type} anomaly detected with payload ${payload}`;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
    // PRIMARY API
    generateAIResponse,
    getStatus,
    resetCache,
    resolveModel,
    pullModel,

    // Domain helpers
    decideStrategy,
    analyzeAttackResult,
    nextStrategy,
    analyzeProxyRequest,
    generateReportDetails,

    // Legacy shims (backward compat)
    streamOllama,
    generatePayloads,
    analyzeResponse,
};
