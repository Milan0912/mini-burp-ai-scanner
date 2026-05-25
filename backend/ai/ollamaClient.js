'use strict';
const axios = require('axios');
const { URL } = require('url');

const ANTHROPIC_BASE = process.env.ANTHROPIC_API_BASE || 'https://api.anthropic.com';
const DEFAULT_MODEL = process.env.ANTHROPIC_MODEL || 'claude-3.5-mini';
const DEFAULT_TIMEOUT_MS = 30000;

let _apiKey = process.env.ANTHROPIC_API_KEY || null;

function getApiKey() {
  _apiKey = process.env.ANTHROPIC_API_KEY || _apiKey;
  return _apiKey;
}

function buildAnthropicPrompt(prompt, system = '') {
  let result = '';
  if (system) {
    result += `System: ${system}\n\n`;
  }
  result += `Human: ${prompt}\n\nAssistant:`;
  return result;
}

async function getInstalledModels() {
  const provider = (process.env.AI_PROVIDER || '').toLowerCase();
  if (provider === 'ollama') {
    const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
    try {
      const res = await axios.get(`${ollamaBaseUrl}/api/tags`, { timeout: 3000 });
      if (res.status === 200 && res.data && res.data.models) {
        return res.data.models.map(m => m.name);
      }
    } catch (e) {
      return null;
    }
  }
  const apiKey = getApiKey();
  if (!apiKey) return null;
  return [DEFAULT_MODEL];
}

async function resolveModel() {
  const provider = (process.env.AI_PROVIDER || '').toLowerCase();
  if (provider === 'ollama') {
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3';
    return ollamaModel;
  }
  const apiKey = getApiKey();
  if (!apiKey) return null;
  return DEFAULT_MODEL;
}

async function generateAIResponse(prompt, options = {}) {
  const provider = (process.env.AI_PROVIDER || '').toLowerCase();
  const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
  const ollamaModel = process.env.OLLAMA_MODEL || 'llama3';

  if (provider === 'ollama') {
    const {
      system = '',
      json = false,
      timeout = DEFAULT_TIMEOUT_MS,
      model = ollamaModel,
      temperature = 0.2,
    } = options;

    try {
      const res = await axios.post(
        `${ollamaBaseUrl}/api/generate`,
        {
          model,
          prompt: system ? `${system}\n\n${prompt}` : prompt,
          stream: false,
          format: json ? 'json' : undefined,
          options: {
            temperature
          }
        },
        {
          timeout
        }
      );
      const text = res?.data?.response;
      if (!text || typeof text !== 'string') return null;

      let rawText = text.trim();
      if (json) {
        rawText = rawText.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/\s*```$/i, '').trim();
        try {
          return JSON.parse(rawText);
        } catch {
          const match = rawText.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
          if (match) {
            try {
              return JSON.parse(match[1]);
            } catch {}
          }
          return null;
        }
      }
      return rawText;
    } catch (err) {
      console.warn(`[OllamaClient] Request failed: ${err.message}`);
      return null;
    }
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    console.warn('[AnthropicClient] Missing ANTHROPIC_API_KEY.');
    return null;
  }

  const {
    system = '',
    json = false,
    timeout = DEFAULT_TIMEOUT_MS,
    model = DEFAULT_MODEL,
    maxTokens = 1024,
    temperature = 0.2,
    stopSequences = ['\n\nHuman:'],
  } = options;

  const anthropicPrompt = buildAnthropicPrompt(prompt, system);

  try {
    const response = await axios.post(
      `${ANTHROPIC_BASE}/v1/complete`,
      {
        model,
        prompt: anthropicPrompt,
        max_tokens_to_sample: maxTokens,
        temperature,
        stop_sequences: stopSequences,
      },
      {
        timeout,
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey,
        },
      }
    );

    const completion = response?.data?.completion;
    if (!completion || typeof completion !== 'string') {
      return null;
    }

    let rawText = completion.trim();
    if (json) {
      rawText = rawText.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/\s*```$/i, '').trim();
      try {
        return JSON.parse(rawText);
      } catch {
        const match = rawText.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
        if (match) {
          try {
            return JSON.parse(match[1]);
          } catch {}
        }
        return null;
      }
    }

    return rawText;
  } catch (err) {
    console.warn(`[AnthropicClient] Request failed: ${err.message}`);
    return null;
  }
}

async function decideStrategy(context) {
  const prompt = `\nYou are an elite bug bounty hunter analyzing a web endpoint.\n\nURL: ${context.url}\nMethod: ${context.method}\nParameters: ${JSON.stringify(context.params || {})}\nContent-Type: ${context.contentType || 'unknown'}\nPage Sample: ${(context.pageContentSnippet || '').slice(0, 400)}\n\nIdentify the endpoint type and choose the best attack vectors.\n\nRules:\n- login page → prioritize SQL Auth Bypass\n- search/query params → prioritize XSS\n- id/uid numeric params → prioritize SQLi Boolean + IDOR\n- file/path params → prioritize LFI\n- admin/dashboard → prioritize IDOR + privilege escalation\n\nOutput ONLY valid JSON:\n{\n  "endpoint_type": "login|search|profile|api|admin|generic",\n  "attack_plan": ["vector1", "vector2"],\n  "priority": "high|medium|low",\n  "reasoning": "brief technical reason",\n  "initial_payloads": [{"vector": "sqli", "payload": "payload_here"}]\n}`;
  const result = await generateAIResponse(prompt, { json: true, timeout: 20000 });
  return result || _heuristicStrategy(context);
}

async function analyzeAttackResult(data) {
  const prompt = `\nYou are a penetration tester analyzing an attack result. Be concise, no theory.\n\nURL: ${data.url}\nPayload: ${data.payload}\nBaseline → Status: ${data.baseline.status}, Length: ${data.baseline.length}\nAttack   → Status: ${data.test.status}, Length: ${data.test.length}, Redirect: ${data.test.redirect || 'none'}, Time: ${data.test.elapsed}ms\n\nDetection rules:\n1. Status 302 to non-login page after auth payload → SQL Auth Bypass (CRITICAL)\n2. Response length diff > 200 bytes → possible injection\n3. Payload reflected verbatim → XSS\n4. Response time > 4000ms with sleep payload → Blind SQLi\n5. No signal → reject\n\nOutput ONLY valid JSON:\n{\n  "is_vulnerable": true,\n  "type": "sqli|xss|idor|lfi|none",\n  "confidence": 0-100,\n  "reason": "technical reason",\n  "next_action": "continue|change_vector|exploit",\n  "next_payloads": []\n}`;
  const result = await generateAIResponse(prompt, { json: true, timeout: 20000 });
  return result || { is_vulnerable: false, confidence: 0, next_action: 'continue' };
}

async function nextStrategy(context) {
  const prompt = `\nYou are an adaptive exploit engineer. Previous payloads failed.\n\nFailed vectors: ${JSON.stringify(context.failed_vectors || [])}\nPrevious attempts: ${JSON.stringify((context.previous_attempts || []).slice(-5))}\nPatterns observed: ${context.response_patterns || 'none'}\n\nSuggest alternative attack approach.\n\nOutput ONLY valid JSON:\n{\n  "next_vector": "vector_name",\n  "new_payloads": ["payload1", "payload2", "payload3"],\n  "strategy": "brief reasoning"\n}`;
  const result = await generateAIResponse(prompt, { json: true, timeout: 15000 });
  return result || _heuristicNextStrategy(context);
}

async function analyzeProxyRequest(ctx) {
  let params = {};
  try {
    const urlObj = new URL(ctx.url);
    params = Object.fromEntries(urlObj.searchParams);
  } catch {}

  const prompt = `\nAnalyze this intercepted HTTP request for security vulnerabilities.\nURL: ${ctx.url}\nMethod: ${ctx.method}\nBody: ${(ctx.body || '').slice(0, 300)}\nParams: ${JSON.stringify(params)}\n\nOutput ONLY valid JSON:\n{\n  "risky_parameters": ["param1"],\n  "possible_vulnerabilities": ["SQLi", "XSS"],\n  "payload_suggestions": [{"param": "id", "payload": "1' OR 1=1--"}],\n  "reasoning": "brief explanation"\n}`;

  const result = await generateAIResponse(prompt, {
    system: 'You are a passive security analyzer for a bug bounty proxy. Do NOT attack, only analyze.',
    json: true,
    timeout: 15000,
  });
  return result;
}

async function generateReportDetails(finding) {
  const prompt = `Write a concise professional bug bounty report for this verified vulnerability: ${JSON.stringify(finding)}`;
  return await generateAIResponse(prompt, { timeout: 20000 });
}

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
    strategy: 'heuristic rotation (AI offline)',
  };
}

async function getStatus() {
  const provider = (process.env.AI_PROVIDER || '').toLowerCase();
  if (provider === 'ollama') {
    const installed = await getInstalledModels();
    return {
      online: installed !== null,
      activeModel: process.env.OLLAMA_MODEL || 'llama3',
      installedModels: installed || [],
      apiBase: process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434',
    };
  }
  const installed = await getInstalledModels();
  return {
    online: installed !== null,
    activeModel: DEFAULT_MODEL,
    installedModels: installed || [],
    apiBase: ANTHROPIC_BASE,
  };
}

function resetCache() {
  _apiKey = process.env.ANTHROPIC_API_KEY || null;
}

async function pullModel(modelName) {
  const provider = (process.env.AI_PROVIDER || '').toLowerCase();
  if (provider === 'ollama') {
    const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
    const res = await axios.post(`${ollamaBaseUrl}/api/pull`, { name: modelName }, { timeout: 600000 });
    return res.data;
  }
  throw new Error('Anthropic does not support local model pulls. Set ANTHROPIC_API_KEY to use remote inference.');
}

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

module.exports = {
  generateAIResponse,
  getStatus,
  resetCache,
  resolveModel,
  pullModel,
  decideStrategy,
  analyzeAttackResult,
  nextStrategy,
  analyzeProxyRequest,
  generateReportDetails,
  streamOllama,
  generatePayloads,
  analyzeResponse,
};
