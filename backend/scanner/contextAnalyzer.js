// contextAnalyzer.js
// Reflection context analyzer for MiniBurp

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isReflected(payload, body) {
  if (!payload || !body) return false;
  
  const lowerBody = body.toLowerCase();
  const lowerPayload = payload.toLowerCase();
  
  // 1. Verbatim raw reflection
  if (body.includes(payload)) return true;
  
  // 2. Case-insensitive reflection
  if (lowerBody.includes(lowerPayload)) return true;
  
  // 3. URL encoded reflection
  const urlEncoded = encodeURIComponent(payload);
  if (body.includes(urlEncoded) || lowerBody.includes(urlEncoded.toLowerCase())) return true;
  
  // 4. Double URL encoded reflection
  const doubleUrlEncoded = encodeURIComponent(urlEncoded);
  if (body.includes(doubleUrlEncoded) || lowerBody.includes(doubleUrlEncoded.toLowerCase())) return true;
  
  // 5. HTML Entity encoded reflection (decimal/named)
  const htmlEntityEncoded = payload
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  if (body.includes(htmlEntityEncoded) || lowerBody.includes(htmlEntityEncoded.toLowerCase())) return true;
  
  // 5b. Hex HTML Entity encoded reflection (case-insensitive for hex characters)
  const hexEntityEncodedLower = payload
      .replace(/&/g, '&#x26;')
      .replace(/</g, '&#x3c;')
      .replace(/>/g, '&#x3e;')
      .replace(/"/g, '&#x22;')
      .replace(/'/g, '&#x27;');
  const hexEntityEncodedUpper = payload
      .replace(/&/g, '&#X26;')
      .replace(/</g, '&#X3C;')
      .replace(/>/g, '&#X3E;')
      .replace(/"/g, '&#X22;')
      .replace(/'/g, '&#X27;');
  if (body.includes(hexEntityEncodedLower) || lowerBody.includes(hexEntityEncodedLower.toLowerCase()) ||
      body.includes(hexEntityEncodedUpper) || lowerBody.includes(hexEntityEncodedUpper.toLowerCase())) return true;

  // 6. Sanitized reflection (alphanumeric match)
  const cleanPayload = payload.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  if (cleanPayload.length > 3) {
      const cleanBody = body.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
      if (cleanBody.includes(cleanPayload)) return true;
  }
  
  return false;
}

/**
 * Determines the context of a reflected payload.
 * @param {string} body - The response body.
 * @param {string} payload - The reflected payload.
 * @returns {string} The reflection context (e.g., HTML, attribute, script).
 */
function determineContext(body, payload) {
  const lowerBody = body.toLowerCase();
  const lowerPayload = payload.toLowerCase();

  // Look inside tag boundaries or script blocks
  if (lowerBody.includes(`<script>${lowerPayload}</script>`) || 
      (lowerBody.includes(`<script>`) && lowerBody.includes(lowerPayload) && 
       lowerBody.indexOf(lowerPayload) > lowerBody.indexOf('<script>') && 
       (lowerBody.indexOf('</script>') === -1 || lowerBody.indexOf(lowerPayload) < lowerBody.indexOf('</script>')))) {
      return 'script';
  }
  
  // Check if it's reflected inside an attribute like name="payload" or name='payload'
  try {
    const escaped = escapeRegExp(lowerPayload);
    if (new RegExp(`=["'][^"'>]*${escaped}[^"'>]*["']`, 'i').test(body)) {
        return 'attribute';
    }
  } catch (e) {}

  if (lowerBody.includes(lowerPayload)) {
      return 'HTML';
  }
  
  return 'unknown';
}

/**
 * Checks if a reflected payload is sanitized.
 * @param {string} body - The response body.
 * @param {string} payload - The reflected payload.
 * @returns {boolean} True if sanitized, false otherwise.
 */
function isSanitized(body, payload) {
  if (payload.includes('<') || payload.includes('>') || payload.includes('"') || payload.includes("'")) {
    if (!body.includes(payload)) {
      return true;
    }
  }
  return false;
}

/**
 * Calculates confidence based on reflection analysis.
 * @param {boolean} reflected - Whether the payload is reflected.
 * @param {boolean} sanitized - Whether the reflection is sanitized.
 * @param {string} context - The reflection context.
 * @returns {number} Confidence score (0-100).
 */
function calculateReflectionConfidence(reflected, sanitized, context) {
  if (!reflected) return 0;
  if (reflected && !sanitized && context === 'script') return 95;
  if (reflected && !sanitized && context === 'HTML') return 85;
  if (reflected && !sanitized) return 70;
  return 55;
}

/**
 * Analyzes the reflection context of a payload in an HTTP response.
 * @param {string} payload - The payload used in the request.
 * @param {Object} response - The HTTP response to analyze.
 * @returns {Object} Reflection analysis result.
 */
async function analyzeReflection(payload, response) {
  try {
      const body = response.body || '';

      // Check if payload is reflected
      const reflected = isReflected(payload, body);

      // Determine reflection context
      const context = determineContext(body, payload);

      // Check if reflection is sanitized
      const sanitized = isSanitized(body, payload);

      // Calculate confidence
      const confidence = calculateReflectionConfidence(reflected, sanitized, context);

      return {
          reflected,
          context,
          sanitized,
          confidence,
      };
  } catch (error) {
      console.error('Reflection analysis failed:', error);
      throw error;
  }
}

module.exports = {
  analyzeReflection,
  determineContext,
  isSanitized,
  calculateReflectionConfidence,
  isReflected,
};