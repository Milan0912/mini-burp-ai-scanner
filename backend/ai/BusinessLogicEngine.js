'use strict';

/**
 * Business Logic Engine
 * =====================
 * Detects parameter tampering, state manipulation, and broken workflows.
 */

class BusinessLogicEngine {
  constructor(io) {
    this.io = io;
  }

  log(phase, message) {
    if (this.io) this.io.emit('logic:log', { phase, message, timestamp: Date.now() });
    console.log(`[BusinessLogic] [${phase}] ${message}`);
  }

  /**
   * Price/Value Tampering Detection
   */
  async checkTampering(reqCtx, param, originalValue, tester) {
    if (!/price|amount|cost|total|id|status/i.test(param)) return null;

    this.log('TEST', `Testing price/parameter tampering on ${param}...`);
    
    // 1. Logic: If value is 100, try 0.01 or -1 or 0
    const tamperedValue = originalValue.replace(/[0-9]+/, '0.01');
    const res = await tester.sendMeasuredRequest(tester.mutateRequest(reqCtx, { param }, tamperedValue));
    
    // Evaluate if server accepted it
    if (res && res.status === 200 && !res.body.toLowerCase().includes('error')) {
      return {
        type: 'Parameter Tampering',
        parameter: param,
        payload: tamperedValue,
        severity: 'High',
        impact: 'Potential price manipulation or session state corruption.',
        evidence: `Server accepted tampered value ${tamperedValue} for ${param}.`
      };
    }
    return null;
  }

  /**
   * Action/Method Tampering
   */
  async checkVerbTampering(reqCtx, tester) {
    const verbs = ['PUT', 'DELETE', 'OPTIONS', 'PATCH'];
    for (const v of verbs) {
      if (v === reqCtx.method) continue;
      const res = await tester.sendMeasuredRequest({ ...reqCtx, method: v });
      if (res && res.status === 200) {
        return {
          type: 'Unprotected Method',
          parameter: 'HTTP METHOD',
          payload: v,
          severity: 'Medium',
          impact: 'Server allows potentially dangerous HTTP verbs.',
          evidence: `Method ${v} allowed on ${reqCtx.url}`
        };
      }
    }
    return null;
  }
}

module.exports = BusinessLogicEngine;
