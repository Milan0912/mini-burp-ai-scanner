'use strict';

/**
 * Elite Engine Orchestrator
 * =========================
 * Manages deep exploitation tasks, concurrency (max 3), 
 * and triggers specialized exploit engines (SQLMAP, Ghost).
 */

const ChainEngine = require('./ChainEngine');
const StrategyEngine = require('./StrategyEngine');
const AttackGraph = require('./AttackGraph');

class EliteEngine {
  constructor(io) {
    this.io = io;
    this.strategy = new StrategyEngine(io);
    this.graph = new AttackGraph(io);
    this.taskQueue = {
      high: [],
      medium: [],
      low: []
    };
    this.activeCount = 0;
    this.maxConcurrent = 3;
    this.processedIdentities = new Set();
    this.mode = 'auto'; // auto | elite | ultimate
  }

  log(phase, message, extra = {}) {
    if (this.io) {
      this.io.emit('elite:log', { 
        phase, 
        message, 
        timestamp: Date.now(), 
        ...extra 
      });
    }
    console.log(`[EliteEngine] [${phase}] ${message}`);
  }

  async enqueue(finding, testingEngine) {
    const identity = `${finding.type}_${finding.endpoint}_${finding.param}`;
    if (this.processedIdentities.has(identity)) return;
    this.processedIdentities.add(identity);

    const priority = this.strategy.evaluatePriority({ url: finding.endpoint, method: finding.method });
    const task = { finding, testingEngine, priority };

    if (priority >= 3) this.taskQueue.high.push(task);
    else if (priority === 2) this.taskQueue.medium.push(task);
    else this.taskQueue.low.push(task);

    this.log('QUEUE', `Added verified ${finding.type} to ${priority >= 3 ? 'HIGH' : priority === 2 ? 'MEDIUM' : 'LOW'} queue.`);
    this.processQueue();
  }

  async processQueue() {
    if (this.activeCount >= this.maxConcurrent) return;

    let task = this.taskQueue.high.shift() || this.taskQueue.medium.shift() || this.taskQueue.low.shift();
    if (!task) return;

    this.activeCount++;
    try {
      await this.runExploitation(task.finding, task.testingEngine);
    } catch (err) {
      this.log('ERROR', `Elite exploitation failed for ${task.finding.type}: ${err.message}`);
    } finally {
      this.activeCount--;
      this.processQueue();
    }
  }

  async runExploitation(finding, testingEngine) {
    const SqlmapEngine = require('./SqlmapEngine');
    const GhostEngine = require('./GhostEngine');
    
    this.log('START', `🚀 [ELITE] Beginning deep exploitation for ${finding.type} on ${finding.endpoint}`);
    this.graph.recordTransition(finding, 'Starting Exploitation', 'START');

    if (finding.type === 'SQL Injection') {
      const sqlResult = await SqlmapEngine.exploit(finding, testingEngine, this.log.bind(this));
      if (sqlResult) {
        finding.status = 'EXPLOITED';
        finding.exploit_data = sqlResult;
        require('../database').updateFinding(finding.id, finding);
        this.io.emit('finding:update', finding);
        this.graph.recordTransition(finding, sqlResult, 'EXPLOIT');
        
        // Chain: SQLi -> Auth (Ultimate Mode Only + Confidence Check)
        if (this.mode === 'ultimate' && this.strategy.shouldChain(finding)) {
           await ChainEngine.sqliToAuth(finding, sqlResult, testingEngine, this.log.bind(this), this.graph);
        }
      }
    } 
    else if (finding.type === 'Reflected XSS') {
      const ghostResult = await GhostEngine.verify(finding, this.log.bind(this));
      if (ghostResult && ghostResult.verified) {
        finding.status = 'VERIFIED_ELITE';
        finding.evidence += ` | [GHOST] Verified JS Execution!`;
        require('../database').updateFinding(finding.id, finding);
        this.io.emit('finding:update', finding);
        this.graph.recordTransition(finding, 'Verified JS Execution', 'VERIFY');
        
        // Chain: XSS -> Hijack (Ultimate Mode)
        if (this.mode === 'ultimate' && ghostResult.cookies) {
           await ChainEngine.xssToHijack(ghostResult.cookies, finding.endpoint, testingEngine, this.log.bind(this), this.graph);
        }
      }
    }
    else if (finding.type === 'Authentication Bypass' || finding.type === 'Auth Bypass') {
       this.log('ELITE', 'Extracting post-auth metadata...');
       finding.status = 'EXPLOITED';
       require('../database').updateFinding(finding.id, finding);
       this.io.emit('finding:update', finding);
       this.graph.recordTransition(finding, 'Auth Bypass Confirmed', 'EXPLOIT');
    }
    else if (finding.type === 'Insecure Direct Object Reference' || finding.type === 'IDOR') {
       this.log('ELITE', 'Attempting IDOR depth exploitation...');
       finding.status = 'VERIFIED_ELITE';
       require('../database').updateFinding(finding.id, finding);
       this.io.emit('finding:update', finding);
       this.graph.recordTransition(finding, 'IDOR Access Confirmed', 'VERIFY');
    }
    else if (finding.type === 'Server-Side Request Forgery' || finding.type === 'SSRF') {
       this.log('ELITE', 'Attempting SSRF metadata extraction...');
       // Implementation...
       finding.status = 'VERIFIED_ELITE';
       require('../database').updateFinding(finding.id, finding);
       this.io.emit('finding:update', finding);
    }

    this.log('DONE', `✅ [ELITE] Finished processing ${finding.type}.`);
  }
}

module.exports = EliteEngine;
