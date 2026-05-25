// timingAnalysis.js
// Timing analysis engine for MiniBurp

/**
 * Analyzes timing delays between baseline and injected responses.
 * @param {Object} normalResponse - The baseline HTTP response.
 * @param {Object} injectedResponse - The HTTP response after payload injection.
 * @returns {Object} Timing analysis result with confidence score.
 */
async function analyzeDelay(normalResponse, injectedResponse) {
    try {
        const baselineTime = measureBaseline(normalResponse);
        const injectedTime = measureBaseline(injectedResponse);

        const delay = Math.abs(injectedTime - baselineTime);
        const confidence = calculateTimingConfidence(delay);

        return {
            delay,
            confidence,
            significant: confidence > 50,
        };
    } catch (error) {
        console.error('Timing analysis failed:', error);
        throw error;
    }
}

/**
 * Measures the baseline timing of a response.
 * @param {Object} response - The HTTP response to measure.
 * @returns {number} Baseline timing in milliseconds.
 */
function measureBaseline(response) {
    // Extract timing from response metadata (handling both time and timing properties)
    return response?.time || response?.timing || 0;
}

/**
 * Calculates confidence based on timing delay.
 * @param {number} delay - The timing delay in milliseconds.
 * @returns {number} Confidence score (0-100).
 */
function calculateTimingConfidence(delay) {
    if (delay > 1000) return 90; // High confidence for significant delays
    if (delay > 500) return 70;  // Medium confidence for moderate delays
    return 30;                   // Low confidence for small delays
}

module.exports = {
    analyzeDelay,
    measureBaseline,
    calculateTimingConfidence,
};