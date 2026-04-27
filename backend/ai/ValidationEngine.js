'use strict';

/**
 * ValidationEngine.js
 * ===================
 * ONE responsibility: Verify if an attack result is a real vulnerability.
 * Performs heuristic scoring and behavioral analysis.
 */

function validate(baseline, attack, context) {
    const { type, payload } = context;
    let score = 0;
    let signals = [];

    // 1. Status/Redirect Analysis (+40 max)
    if (attack.status !== baseline.status) {
        score += 20; 
        signals.push(`Status Shift (${baseline.status} -> ${attack.status})`);
        
        if (attack.status === 302 || attack.status === 200) {
            score += 20;
            signals.push(`Potential bypass success`);
        }
    }

    if ((attack.redirect || '') !== (baseline.redirect || '')) {
        score += 40;
        signals.push(`Redirect Shift (${baseline.redirect} -> ${attack.redirect})`);
    }

    // 2. Diff Length Analysis (Loose)
    const diff = Math.abs(attack.length - baseline.length);
    if (diff > 15) {
        score += 10;
        signals.push(`Length Delta (${diff} bytes)`);
    }

    // 3. Keyword / Logical Differences
    const body = (attack.body || '').toLowerCase();
    
    if (type === 'sqli') {
        const errors = ['sql syntax','mysql_fetch','ora-','postgre','incorrect syntax','unclosed quotation', 'microsoft ole db','odbc source'];
        if (errors.some(e => body.includes(e))) {
            score += 40;
            signals.push('SQL Syntax Error (Vendor Specific)');
        }

        if (body.includes('welcome') || body.includes('dashboard') || body.includes('logout') || body.includes('logged in')) {
            if (!baseline.body.toLowerCase().includes('welcome') && !baseline.body.toLowerCase().includes('logout')) {
                score += 40;
                signals.push('Keyword difference (+20 bonus)');
                signals.push('Auth bypass keyword detected');
            }
        }
    }

    if (type === 'xss') {
        // Issue 4: Allow partial reflection and check common encodings
        const payloadDecoded = decodeURIComponent(payload).toLowerCase();
        if (body.includes(payload.toLowerCase()) || body.includes(payloadDecoded)) {
            score = 100;
            signals.push('XSS Reflection Confirmed');
        } else if (payload.length > 5 && body.includes(payload.slice(0, 5).toLowerCase())) {
            score += 40;
            signals.push('Partial XSS Reflection (Suspicious)');
        }
    }

    return { 
        isValid: score > 0 || signals.length > 0, 
        isConfirmed: score >= 90, 
        score, 
        signals 
    };
}

function verifyConsistency(res1, res2) {
    if (res1.status !== res2.status) return false;
    if (Math.abs(res1.length - res2.length) > 100) return false;
    return true;
}

module.exports = { validate, verifyConsistency };
