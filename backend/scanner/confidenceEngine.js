// confidenceEngine.js
// Centralized confidence scoring for MiniBurp verification

/**
 * Calculate a combined confidence score and level based on multiple signals.
 * @param {Object} signals - The input signals e.g. { diffResult, timingResult, contextResult, aiResult }
 * @returns {Object} { score, level, reasoning }
 */
function calculateConfidence(signals = {}, finding = {}) {
    try {
        const { diffResult = {}, timingResult = {}, contextResult = {}, aiResult = null } = signals;
        const type = (finding.type || '').toLowerCase();

        // Start with a neutral base or the finding's score if available
        let score = finding.score || 50;
        const reasons = [];

        // Determine if we should skip similarity penalty
        const isTimeSqli = type.includes('time');
        const isXss = type.includes('xss') || type.includes('template') || type.includes('ssti');
        const isBooleanSqli = type.includes('boolean');

        const skipSimilarityPenalty = isTimeSqli || isXss || isBooleanSqli;

        if (skipSimilarityPenalty) {
            reasons.push('Similarity penalty skipped');
        } else {
            // Diff similarity: higher similarity reduces confidence in behavioral change
            const similarity = typeof diffResult.similarityScore === 'number' ? diffResult.similarityScore : (diffResult.similarity || 50);
            if (similarity >= 90) {
                score -= 20;
                reasons.push('Responses nearly identical');
            } else if (similarity >= 60) {
                score -= 5;
                reasons.push('Partial response similarity');
            } else {
                score += 15;
                reasons.push('Significant response differences');
            }
        }

        // Anomalies from diff
        if (Array.isArray(diffResult.anomalies) && diffResult.anomalies.length > 0) {
            score += Math.min(20, diffResult.anomalies.length * 5);
            reasons.push(`Detected ${diffResult.anomalies.length} response anomalies`);
        }

        // Timing signals
        if (timingResult && typeof timingResult.confidence === 'number') {
            if (isTimeSqli && timingResult.significant) {
                score = Math.max(score, 85);
                reasons.push('Significant timing delay detected (base score 85)');
            } else {
                score += Math.round((timingResult.confidence - 50) / 10);
                reasons.push(`Timing confidence ${timingResult.confidence}`);
            }
        }

        // Reflection context
        if (contextResult && typeof contextResult.confidence === 'number') {
            if (isXss) {
                score = contextResult.confidence;
                reasons.push(`XSS Reflection confidence ${contextResult.confidence} set as base`);
            } else {
                score += Math.round((contextResult.confidence - 50) / 10);
                reasons.push(`Reflection confidence ${contextResult.confidence}`);
            }
        }

        // AI result overrides or boosts
        if (aiResult && typeof aiResult.confidence === 'number') {
            score = Math.round((score * 0.4) + (aiResult.confidence * 0.6));
            reasons.push(`AI confidence ${aiResult.confidence}`);
            if (aiResult.confirmed === true) reasons.push('AI confirmed vulnerability');
            if (aiResult.confirmed === false) reasons.push('AI suggested false positive');
        }

        // Clamp score
        score = Math.max(0, Math.min(100, score));

        // Determine level (80+ VERIFIED, 50+ LIKELY, 20+ INFORMATIONAL)
        let level = 'INFORMATIONAL';
        if (score >= 80) level = 'VERIFIED';
        else if (score >= 50) level = 'LIKELY';
        else level = 'INFORMATIONAL';

        return {
            score,
            level,
            reasoning: reasons.join('; '),
        };
    } catch (err) {
        console.error('Confidence calculation failed:', err);
        return { score: 0, level: 'INFORMATIONAL', reasoning: 'Error calculating confidence' };
    }
}

module.exports = {
    calculateConfidence,
};