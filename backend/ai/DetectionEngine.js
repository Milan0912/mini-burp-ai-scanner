'use strict';

const SmartCompare = require('./SmartCompare');
const aiModel = require('./aiModel');

/**
 * DetectionEngine.js
 * ==================
 * The central brain for vulnerability detection.
 * Combines high-fidelity heuristics with AI verification.
 */

async function detect(baseline, testRes, context) {
    // 1. Heuristic Check
    const evalResult = SmartCompare.compare(baseline, testRes, context);

    if (evalResult.isSuspicious) {
        console.log(`[DetectionEngine] Anomaly detected (${evalResult.score}). Triggering AI verification...`);
        
        // 2. AI Verification (Task 4)
        const aiVerify = await aiModel.verifyAnomaly({
            type: context.type,
            payload: context.payload,
            baseline,
            test: testRes,
            signals: evalResult.signals,
            score: evalResult.score
        });

        return {
            isConfirmed: aiVerify.isVulnerable && aiVerify.confidence >= 70,
            confidence: aiVerify.confidence,
            reasoning: aiVerify.reasoning,
            next_payloads: aiVerify.next_payloads || []
        };
    }

    return { isConfirmed: false, confidence: 0, reasoning: 'No anomaly detected' };
}

module.exports = { detect };
