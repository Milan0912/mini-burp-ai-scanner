'use strict';

/**
 * SmartCompare.js — Autonomous Response Evaluator
 * ===============================================
 * Handles high-fidelity comparison and double-validation.
 */

function evaluate(baseline, test, context = {}) {
    const { type, payload } = context;
    let score = 0;
    let signals = [];

    // 1. Status Transformation
    if (test.status !== baseline.status) {
        if (test.status === 200 && baseline.status >= 300) {
            score += 70;
            signals.push(`Status Upgrade (bypass detected: ${test.status})`);
        } else if ([500, 403, 401].includes(test.status)) {
            score += 40;
            signals.push(`Status Shift (${test.status})`);
        }
    }

    // 2. Length Delta
    const diff = Math.abs(test.length - baseline.length);
    if (diff > Math.max(200, baseline.length * 0.1)) {
        score += 30;
        signals.push(`Significant Length Delta (${diff} bytes)`);
    }

    // 3. Vector-Specific Signals
    const body = (test.body || '').toLowerCase();
    
    if (type === 'sqli') {
        const errors = ['sql syntax','mysql_fetch','ora-','postgre','incorrect syntax','unclosed quotation'];
        if (errors.some(e => body.includes(e))) {
            score = 100;
            signals.push('SQL Syntax Error');
        }
        if (test.elapsed > 4500 && baseline.avgTime < 1500) {
            score = 100;
            signals.push('Time-based SQLi');
        }
    }

    if (type === 'xss') {
        if (body.includes(payload.toLowerCase())) {
            score = 100;
            signals.push('Reflection detected');
        }
    }
    
    if (test.status === 302 && test.redirect && !test.redirect.toLowerCase().includes('login')) {
         score += 60;
         signals.push(`Unauthorized Redirect: ${test.redirect}`);
    }

    return { score, signals };
}

/**
 * TASK 4: DOUBLE VALIDATION
 * Compares two attack responses to ensure the signal is persistent.
 */
function isConsistent(res1, res2) {
    if (res1.status !== res2.status) return false;
    const lenDiff = Math.abs(res1.length - res2.length);
    if (lenDiff > 100) return false;
    return true;
}

module.exports = { evaluate, isConsistent };
