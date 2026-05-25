// responseDiffEngine.js
// Advanced HTTP response comparison system for MiniBurp

/**
 * Compares two HTTP responses and identifies differences.
 * @param {Object} normalResponse - The baseline HTTP response.
 * @param {Object} injectedResponse - The HTTP response after payload injection.
 * @returns {Object} Result with similarity score and detected anomalies.
 */
async function diffResponses(normalResponse, injectedResponse) {
    try {
        const anomalies = [];
        const normalBody = normalResponse?.body || '';
        const injectedBody = injectedResponse?.body || '';

        // Compare response lengths
        if (normalBody.length !== injectedBody.length) {
            anomalies.push('Response length mismatch');
        }

        // Compare status codes
        const normalStatus = normalResponse?.status || normalResponse?.statusCode || 0;
        const injectedStatus = injectedResponse?.status || injectedResponse?.statusCode || 0;
        if (normalStatus !== injectedStatus) {
            anomalies.push('Status code mismatch');
        }

        // Compare headers
        const headerDiffs = compareHeaders(normalResponse?.headers || {}, injectedResponse?.headers || {});
        if (headerDiffs.length > 0) {
            anomalies.push('Header differences detected');
        }

        // Calculate similarity score (basic example)
        const similarityScore = calculateSimilarity(normalBody, injectedBody);

        return {
            similarityScore,
            anomalies,
            changedSections: headerDiffs,
            confidenceImpact: anomalies.length > 0 ? -10 : 10,
        };
    } catch (error) {
        console.error('Response diffing failed:', error);
        throw error;
    }
}

/**
 * Calculates similarity between two response bodies.
 * @param {string} body1 - The first response body.
 * @param {string} body2 - The second response body.
 * @returns {number} Similarity score (0-100).
 */
function calculateSimilarity(body1, body2) {
    if (!body1 || !body2) return 0;
    if (body1 === body2) return 100;
    const len1 = body1.length, len2 = body2.length;
    const maxLen = Math.max(len1, len2);
    if (maxLen === 0) return 100;
    
    let matchCount = 0;
    const sampleSize = 100;
    const step = Math.max(1, Math.floor(Math.min(len1, len2) / sampleSize));
    for (let i = 0; i < sampleSize; i++) {
        const idx = i * step;
        if (body1[idx] === body2[idx]) matchCount++;
    }
    const charRatio = matchCount / sampleSize;
    const lengthRatio = Math.min(len1, len2) / maxLen;
    return Math.round(charRatio * lengthRatio * 100);
}

/**
 * Compares HTTP headers between two responses.
 * @param {Object} headers1 - The first set of headers.
 * @param {Object} headers2 - The second set of headers.
 * @returns {Array} List of header differences.
 */
function compareHeaders(headers1, headers2) {
    const diffs = [];
    for (const key in headers1) {
        if (headers1[key] !== headers2[key]) {
            diffs.push({ key, value1: headers1[key], value2: headers2[key] });
        }
    }
    return diffs;
}

module.exports = {
    diffResponses,
    calculateSimilarity,
    compareHeaders,
};