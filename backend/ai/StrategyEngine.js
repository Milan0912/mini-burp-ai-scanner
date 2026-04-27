'use strict';

/**
 * Strategy Engine — Intelligent Attack Orchestrator
 */

const { scoreFinding } = require('./cvssCalculator');

class StrategyEngine {
  constructor(io) {
    this.io = io;
    this.taskQueue = {
      high: [],
      medium: [],
      low: []
    };
    this.processedUrls = new Set();
    this.highValuePatterns = [/admin/i, /login/i, /auth/i, /api\/v1/i, /user/i, /config/i, /setting/i];
  }

  /**
   * TASK 1: INTENT DETECTION
   * Classify page types based on URL, HTML context, and inputs.
   */
  detectIntent(reqCtx, html = '', inputs = []) {
    const url = reqCtx.url || '';
    const intent = {
      type: 'generic',
      score: 1,
      critical: false,
      goals: ['discovery']
    };

    // 1. URL Patterns
    if (/login|auth|signin/i.test(url)) {
      intent.type = 'login';
      intent.goals = ['auth-bypass', 'credential-stuffing'];
      intent.critical = true;
    } else if (/admin|dashboard|panel|config/i.test(url)) {
      intent.type = 'admin';
      intent.goals = ['unauth-access', 'priv-esc', 'rce'];
      intent.critical = true;
    } else if (/\/(search|query|find|q)(\.aspx)?/i.test(url)) {
      intent.type = 'search';
      intent.goals = ['xss', 'sqli'];
      intent.critical = true; 
    } else if (/\/(show|image|view|file|get)(\.aspx)?/i.test(url)) {
      intent.type = 'file_handler';
      intent.goals = ['sqli', 'error_disclosure', 'lfi'];
      intent.critical = true;
    } else if (/profile|user|account|my-info/i.test(url)) {
      intent.type = 'profile';
      intent.goals = ['idor', 'pii-leak'];
    } else if (/pay|checkout|order|cart|billing/i.test(url)) {
      intent.type = 'payment';
      intent.goals = ['parameter-tampering', 'price-manipulation'];
      intent.critical = true;
    } else if (/\/api\/|v1|v2|\.json/i.test(url)) {
      intent.type = 'api';
      intent.goals = ['mass-assignment', 'auth-logic', 'sqli'];
    }

    // 2. HTML Content Detection
    if (html) {
      if (/<form[^>]*password/i.test(html)) {
        intent.type = 'login';
        intent.goals.push('sqli-bypass');
      }
      if (/(<input[^>]*(name|id)=["']?search|search|query)/i.test(html)) {
         intent.goals.push('xss');
      }
      if (/credit\s*card|stripe|paypal|cvv/i.test(html)) {
        intent.type = 'payment';
      }
      if (/<table|grid|admin|management/i.test(html) && /admin/i.test(url)) {
        intent.type = 'admin';
      }
    }

    // 3. Form Input Detection
    const paramNames = inputs.map(i => (i.param || '').toLowerCase());
    if (paramNames.includes('username') && paramNames.includes('password')) {
       intent.type = 'login';
    }
    if (paramNames.some(p => /price|amount|cost|total/i.test(p))) {
       intent.goals.push('price-manipulation');
    }

    intent.score = intent.critical ? 3 : (intent.type !== 'generic' ? 2 : 1);
    this.log('INTENT', `Detected ${intent.type.toUpperCase()} intent for ${url}`);
    return intent;
  }

  evaluatePriority(reqCtx, html = '', inputs = []) {
    const intent = this.detectIntent(reqCtx, html, inputs);
    return intent.score;
  }

  addTask(task) {
    const priority = task.priority || 1;
    if (priority >= 3) {
      this.taskQueue.high.push(task);
    } else if (priority === 2) {
      this.taskQueue.medium.push(task);
    } else {
      this.taskQueue.low.push(task);
    }
    this.log('STRATEGY', `Task queued with priority ${priority}: ${task.type || 'Scan'}`);
  }

  getNextTask() {
    if (this.taskQueue.high.length > 0) return this.taskQueue.high.shift();
    if (this.taskQueue.medium.length > 0) return this.taskQueue.medium.shift();
    if (this.taskQueue.low.length > 0) return this.taskQueue.low.shift();
    return null;
  }

  log(phase, message) {
    if (this.io) {
      this.io.emit('strategy:log', { phase, message, timestamp: Date.now() });
    }
    console.log(`[StrategyEngine] [${phase}] ${message}`);
  }

  shouldChain(finding) {
    const confidence = finding.confidence || finding.score || 0;
    if (confidence >= 90) return true;
    
    // Fallback to CVSS check
    try {
      const profiled = scoreFinding(finding);
      return profiled.cvss.score >= 8.5;
    } catch(e) {
      return false;
    }
  }
}

module.exports = StrategyEngine;
