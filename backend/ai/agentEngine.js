'use strict';

/**
 * agentEngine.js
 * ==============
 * Orchestrates AI-assisted suggestions during proxy intercept.
 * Operates in "Suggest" mode only — never auto-attacks.
 */

class AgentEngine {
    constructor() {
        this.io = null;
        this.mode = 'Suggest';
    }

    setIO(io) { this.io = io; }

    setMode(mode) {
        this.mode = 'Suggest'; // Enforce suggestion-only mode
        this.log(`Mode set to: Suggest (auto-attack disabled)`);
        if (this.io) this.io.emit('agent:mode', { mode: 'Suggest' });
    }

    /**
     * Called by insightEngine after findings update.
     * Emits AI-assisted suggestions to the UI without triggering attacks.
     */
    observeFindings(reqId, findings) {
        if (!findings || findings.length === 0) return;
        try {
            const highValue = findings.filter(f => f.severity === 'High' || f.severity === 'Critical');
            if (highValue.length > 0 && this.io) {
                this.io.emit('agent:suggestion', {
                    reqId,
                    message: `High-value signals detected: ${highValue.map(f => f.type).join(', ')}. Consider manual verification.`,
                    findings: highValue,
                    timestamp: new Date().toISOString()
                });
            }
        } catch (e) {
            console.warn('[AgentEngine] observeFindings error:', e.message);
        }
    }

    log(msg, type = 'info') {
        console.log(`[AgentEngine] ${msg}`);
        if (this.io) {
            this.io.emit('agent:log', { message: msg, type, timestamp: new Date().toISOString() });
        }
    }

    getAgentState() {
        return {
            mode: 'Suggest',
            pendingCount: 0,
            pendingQueue: {},
        };
    }
}

module.exports = new AgentEngine();
