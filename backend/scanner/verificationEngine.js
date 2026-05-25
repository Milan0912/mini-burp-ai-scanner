// verificationEngine.js
// Core behavioral verification engine for MiniBurp

const responseDiffEngine = require('./responseDiffEngine');
const timingAnalysis = require('./timingAnalysis');
const contextAnalyzer = require('./contextAnalyzer');
const confidenceEngine = require('./confidenceEngine');

/**
 * Verifies a vulnerability by analyzing responses and behavior.
 * @param {Object} finding - The vulnerability finding to verify.
 * @param {Object} responses - The HTTP responses to analyze.
 * @returns {Object} Verification result with confidence score and evidence.
 */
async function verifyFinding(finding, responses) {
    try {
        const { normalResponse, injectedResponse } = responses;

        // Step 1: Compare responses
        const diffResult = await responseDiffEngine.diffResponses(normalResponse, injectedResponse);

        // Step 2: Analyze timing anomalies
        const timingResult = await timingAnalysis.analyzeDelay(normalResponse, injectedResponse);

        // Step 3: Analyze reflection context (for XSS)
        const contextResult = await contextAnalyzer.analyzeReflection(finding.payload, injectedResponse);

        // Step 4: Calculate confidence score
        const confidenceResult = confidenceEngine.calculateConfidence({
            diffResult,
            timingResult,
            contextResult,
        }, finding);

        // Step 5: Return verification result
        return {
            verified: confidenceResult.level === 'VERIFIED',
            confidence: confidenceResult.score,
            reasoning: confidenceResult.reasoning,
            evidence: {
                diffResult,
                timingResult,
                contextResult,
            },
        };
    } catch (error) {
        console.error('Verification failed:', error);
        return {
            verified: false,
            confidence: 0,
            evidence: null,
            error: error.message,
        };
    }
}

module.exports = {
    verifyFinding,
};