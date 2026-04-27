'use strict';
/**
 * CVSS v3.1 Calculator
 * Automatically scores vulnerabilities based on type and context.
 */

// AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
const CVSS_PROFILES = {
  'SQL Injection': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8, severity: 'Critical',
    description: 'Unauthenticated attacker can extract, modify, or delete all database contents.',
  },
  'SQL Injection (Auth Bypass)': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8, severity: 'Critical',
    description: 'Authentication completely bypassed via SQL injection.',
  },
  'Blind SQL Injection': {
    vector: 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    score: 5.9, severity: 'Medium',
    description: 'Time-based blind SQL injection allows slow data extraction.',
  },
  'XSS': {
    vector: 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    score: 6.1, severity: 'Medium',
    description: 'Cross-site scripting allows session hijacking and credential theft.',
  },
  'Stored XSS': {
    vector: 'AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N',
    score: 6.5, severity: 'Medium',
    description: 'Stored XSS persists and executes for all visitors.',
  },
  'SSRF': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    score: 8.6, severity: 'High',
    description: 'Server-side request forgery exposes internal services.',
  },
  'IDOR': {
    vector: 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    score: 8.1, severity: 'High',
    description: 'Insecure direct object reference exposes any user\'s private data.',
  },
  'Path Traversal': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    score: 7.5, severity: 'High',
    description: 'Directory traversal exposes sensitive server files.',
  },
  'SSTI': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8, severity: 'Critical',
    description: 'Server-side template injection may lead to Remote Code Execution.',
  },
  'Command Injection': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    score: 9.8, severity: 'Critical',
    description: 'Arbitrary OS command execution on the server.',
  },
  'Auth Bypass': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    score: 9.1, severity: 'Critical',
    description: 'Authentication mechanism completely bypassed.',
  },
  'Default': {
    vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    score: 5.3, severity: 'Medium',
    description: 'Behavioral anomaly detected.',
  },
};

function getCVSS(vulnType) {
  const key = Object.keys(CVSS_PROFILES).find(k =>
    vulnType && vulnType.toLowerCase().includes(k.toLowerCase())
  );
  return CVSS_PROFILES[key] || CVSS_PROFILES['Default'];
}

/**
 * Build a full CVSS object for a finding.
 */
function scoreFinding(finding) {
  const cvss = getCVSS(finding.vulnerability_type || finding.type || '');
  return {
    ...finding,
    cvss: {
      score: cvss.score,
      severity: cvss.severity,
      vector: cvss.vector,
      description: cvss.description,
    },
  };
}

module.exports = { getCVSS, scoreFinding, CVSS_PROFILES };
