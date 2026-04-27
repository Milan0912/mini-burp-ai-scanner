'use strict';

/**
 * AI Insight Engine (Central State & Correlation)
 */

class InsightEngine {
  constructor() {
    this.insights = new Map(); // reqId -> { request, response, findings: Map<id, Finding>, attackResults: [] }
    this.baselineCache = new Map(); // [Method]:[URL_Path]:[Params] -> { status, length, timestamp }
    this.io = null;
    this.confirmedCallbacks = [];
  }

  onConfirmed(callback) {
    this.confirmedCallbacks.push(callback);
  }

  setIO(io) {
    this.io = io;
  }

  getOrCreate(reqId) {
    if (!this.insights.has(reqId)) {
      this.insights.set(reqId, {
        reqId,
        request: null,
        response: null,
        findings: new Map(), // Use Map to prevent duplicates
        attackResults: [],
      });
      // Limit memory (store last 2000)
      if (this.insights.size > 2000) {
        const firstKey = this.insights.keys().next().value;
        this.insights.delete(firstKey);
      }
    }
    return this.insights.get(reqId);
  }

  setRequest(reqId, requestContext) {
    const entry = this.getOrCreate(reqId);
    entry.request = requestContext;
  }

  setResponse(reqId, responseContext) {
    const entry = this.getOrCreate(reqId);
    const respObj = {
      status: responseContext.statusCode || responseContext.status,
      length: responseContext.bodyPreview ? Buffer.byteLength(responseContext.bodyPreview, 'utf8') : 0,
    };
    entry.response = respObj;

    // Cache the baseline globally
    if (entry.request) {
      this.cacheBaseline(entry.request, respObj);
    }
    
    // 2. Passive Analysis (Task 4)
    const PassiveAnalyzer = require('./PassiveAnalyzer');
    const fullCtx = {
        reqId,
        url: entry.request ? entry.request.url : '',
        method: entry.request ? entry.request.method : 'GET',
        resHeaders: responseContext.resHeaders || responseContext.headers || {},
        resBody: responseContext.resBody || responseContext.body || '',
        status: respObj.status
    };
    PassiveAnalyzer.analyze(fullCtx);

    this.correlate(reqId);
  }

  cacheBaseline(reqCtx, respObj) {
    try {
      const urlObj = new URL(reqCtx.url.startsWith('http') ? reqCtx.url : `http://localhost${reqCtx.url}`);
      const params = Array.from(urlObj.searchParams.keys()).sort().join(',');
      const key = `${reqCtx.method}:${urlObj.pathname}:${params}`;
      this.baselineCache.set(key, { ...respObj, timestamp: Date.now() });
      
      // Cleanup cache over 5 minutes map
      const fiveMinsAgo = Date.now() - 300000;
      for (const [k, v] of this.baselineCache.entries()) {
        if (v.timestamp < fiveMinsAgo) this.baselineCache.delete(k);
      }
    } catch(e) { }
  }

  getBaseline(reqCtx) {
    try {
      const urlObj = new URL(reqCtx.url.startsWith('http') ? reqCtx.url : `http://localhost${reqCtx.url}`);
      const params = Array.from(urlObj.searchParams.keys()).sort().join(',');
      const key = `${reqCtx.method}:${urlObj.pathname}:${params}`;
      const cached = this.baselineCache.get(key);
      if (cached && Date.now() - cached.timestamp < 300000) return cached;
    } catch(e) { }
    return null;
  }

  /**
   * Calculate severity based on type and confidence.
   * Impacts: SQLi/RCE = High, XSS/IDOR = Medium, Config/Info = Low.
   */
  _calculateSeverity(type, confidence) {
    let impact = 1; // 1=Low, 2=Medium, 3=High
    if (type.includes('SQL') || type.includes('RCE')) impact = 3;
    else if (type.includes('XSS') || type.includes('IDOR')) impact = 2;
    
    let confScore = 1; // 1=Low, 2=Medium, 3=High
    if (confidence === 'High') confScore = 3;
    else if (confidence === 'Medium') confScore = 2;

    const total = impact * confScore;
    if (total >= 8) return 'Critical';
    if (total >= 6) return 'High';
    if (total >= 3) return 'Medium';
    return 'Low';
  }

  /**
   * @param {string} reqId
   * @param {Object} finding
   * finding: { id, type, parameter, confidence (Low/Medium/High), message }
   */
  addRequestInsight(reqId, finding) {
    const entry = this.getOrCreate(reqId);
    finding.severity = this._calculateSeverity(finding.type, finding.confidence);
    // If a finding of the same ID doesn't exist or we are overriding with higher confidence, update
    if (!entry.findings.has(finding.id)) {
      entry.findings.set(finding.id, finding);
      this._emitUpdate(reqId);
    }
  }

  addResponseInsight(reqId, finding) {
    const entry = this.getOrCreate(reqId);
    finding.severity = this._calculateSeverity(finding.type, finding.confidence);
    entry.findings.set(finding.id, finding);
    this.correlate(reqId);
    this._emitUpdate(reqId);
  }

  correlate(reqId) {
    const entry = this.getOrCreate(reqId);
    let changed = false;

    // Check if SQL Error exists in findings, boost SQLi confidence
    let hasSqlError = false;
    for (const f of entry.findings.values()) {
      if (f.id === 'sql_error') hasSqlError = true;
    }

    for (const [id, f] of entry.findings.entries()) {
      if (f.type === 'SQL Injection Candidate' && hasSqlError) {
        if (f.confidence !== 'High') {
          f.confidence = 'High';
          f.severity = this._calculateSeverity(f.type, f.confidence);
          f.message = f.message + ' (Correlated with SQL syntax error in response!)';
          changed = true;
        }
      }
    }

    if (changed) this._emitUpdate(reqId);
  }

  addAttackResult(reqId, type, param, result) {
    const entry = this.getOrCreate(reqId);
    entry.attackResults.push({ type, param, result });
    this._emitUpdate(reqId);

    // If result is confirmed, notify listeners for reporting
    if (result && result.confirmed) {
      const finding = {
        reqId,
        method: entry.request ? entry.request.method : 'GET',
        url: entry.request ? entry.request.url : '',
        param,
        type,
        payload: result.payload,
        responseEvidence: result.evidence
      };
      this.confirmedCallbacks.forEach(cb => cb(finding));
    }
  }

  getInsights(reqId) {
    const entry = this.insights.get(reqId);
    if (!entry) return { findings: [], attackResults: [] };
    return {
      findings: Array.from(entry.findings.values()),
      attackResults: entry.attackResults,
    };
  }

  _emitUpdate(reqId) {
    if (!this.io) return;
    const insights = this.getInsights(reqId);
    this.io.emit('ai:insights:update', { id: reqId, ...insights });

    // Pass data into Agentic Engine to decide next steps autonomously
    const agentEngine = require('./agentEngine');
    agentEngine.observeFindings(reqId, insights.findings);
  }
}

module.exports = new InsightEngine();
