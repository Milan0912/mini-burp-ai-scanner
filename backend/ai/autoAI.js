'use strict';
const axios = require('axios');

const autoAI = {
  mode: null,
  model: null,

  async init() {
    const provider = (process.env.AI_PROVIDER || '').toLowerCase();
    const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3';

    if (provider === 'ollama') {
      let reachable = false;
      try {
        const res = await axios.get(`${ollamaBaseUrl}/api/tags`, { timeout: 3000 });
        if (res.status === 200) reachable = true;
      } catch (e) {
        console.log(`[AutoAI] Ollama service not reachable on ${ollamaBaseUrl}. Attempting to start it...`);
        try {
          const { spawn } = require('child_process');
          const child = spawn('ollama', ['serve'], {
            detached: true,
            stdio: 'ignore',
            shell: true
          });
          child.unref();
          // Wait 3 seconds for start up
          await new Promise(r => setTimeout(r, 3000));
          const res = await axios.get(`${ollamaBaseUrl}/api/tags`, { timeout: 3000 });
          if (res.status === 200) reachable = true;
        } catch (err) {
          console.warn('[AutoAI] Failed to auto-start Ollama:', err.message);
        }
      }

      if (reachable) {
        this.mode = 'ollama';
        this.model = ollamaModel;
        console.log(`[AutoAI] Using configured Ollama model: ${this.model}`);
        return;
      } else {
        console.warn(`[AutoAI] Ollama configured but unreachable. Falling back to rule-based.`);
      }
    } else {
      // If AI_PROVIDER is not set, try auto-detecting a local running Ollama instance
      try {
        const res = await axios.get(`${ollamaBaseUrl}/api/tags`, { timeout: 3000 });
        if (res.status === 200 && res.data && res.data.models) {
          const models = res.data.models.map(m => m.name.split(':')[0]);
          const priority = ['llama3', 'llama3.2', 'mistral', 'llama3.1', 'llama2', 'tinyllama'];
          let selected = null;
          for (const p of priority) {
            if (models.includes(p)) {
              selected = p;
              break;
            }
          }
          if (!selected && models.length > 0) {
            selected = models[0];
          }

          if (selected) {
            this.mode = 'ollama';
            this.model = selected;
            console.log(`[AutoAI] Auto-detected Ollama with model: ${selected}`);
            return;
          }
        }
      } catch (e) {
        // ignore
      }
    }

    this.mode = 'rule-based';
    console.log('[AutoAI] Using Rule-Based Engine (install/run Ollama for AI analysis)');
  },

  getMode() {
    return this.mode || 'rule-based';
  },

  ruleBasedAnalysis(finding) {
    const type = (finding.type || finding.vulnerability_name || 'unknown').toLowerCase();
    
    const rules = {
      sqli: {
        explanation: "SQL Injection allows attackers to manipulate database queries. An attacker can read, modify or delete data from the database.",
        exploitability: "High",
        cvss: 8.8,
        remediation: "Use parameterized queries or prepared statements. Example: db.query('SELECT * FROM users WHERE id = ?', [userId])",
        owasp: "A03:2021 - Injection"
      },
      xss: {
        explanation: "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.",
        exploitability: "Medium",
        cvss: 6.1,
        remediation: "Encode all user output. Use: encodeURIComponent() for URLs, textContent instead of innerHTML",
        owasp: "A03:2021 - Injection"
      },
      ssrf: {
        explanation: "Server-Side Request Forgery tricks the server into making requests to internal services.",
        exploitability: "Critical",
        cvss: 9.8,
        remediation: "Validate and whitelist allowed URLs. Block internal IP ranges: 127.0.0.1, 169.254.x.x, 10.x.x.x",
        owasp: "A10:2021 - Server-Side Request Forgery (SSRF)"
      },
      idor: {
        explanation: "Insecure Direct Object Reference allows users to access other users data by changing an ID value.",
        exploitability: "High",
        cvss: 8.1,
        remediation: "Always verify the logged-in user owns the requested resource before returning data.",
        owasp: "A01:2021 - Broken Access Control"
      },
      csrf: {
        explanation: "Cross-Site Request Forgery tricks users into submitting requests they did not intend to make.",
        exploitability: "Medium",
        cvss: 6.5,
        remediation: "Add CSRF tokens to all state-changing forms. Use SameSite=Strict on session cookies.",
        owasp: "A01:2021 - Broken Access Control"
      },
      lfi: {
        explanation: "Local File Inclusion allows attackers to read sensitive files from the server like /etc/passwd.",
        exploitability: "High",
        cvss: 7.5,
        remediation: "Never use user input in file paths. Use a whitelist of allowed files only.",
        owasp: "A03:2021 - Injection"
      },
      open_redirect: {
        explanation: "Open Redirect allows attackers to redirect users to malicious websites for phishing attacks.",
        exploitability: "Medium",
        cvss: 6.1,
        remediation: "Whitelist allowed redirect destinations. Never redirect to user-supplied URLs.",
        owasp: "A03:2021 - Injection"
      },
      headers: {
        explanation: "Missing security headers leave the application vulnerable to various client-side attacks.",
        exploitability: "Low",
        cvss: 4.3,
        remediation: "Add security headers in your server config: Content-Security-Policy, X-Frame-Options, HSTS",
        owasp: "A05:2021 - Security Misconfiguration"
      },
      command_injection: {
        explanation: "Command Injection allows an attacker to execute arbitrary operating system commands on the host server.",
        exploitability: "Critical",
        cvss: 9.8,
        remediation: "Avoid executing OS commands with user input. Use secure APIs instead.",
        owasp: "A03:2021 - Injection"
      },
      xxe: {
        explanation: "XML External Entity injection occurs when XML parsers process XML input containing reference to an external entity.",
        exploitability: "High",
        cvss: 7.5,
        remediation: "Disable XML external entity and DTD processing in all XML parsers.",
        owasp: "A05:2021 - Security Misconfiguration"
      },
      sensitive_data: {
        explanation: "Sensitive Data Exposure happens when an application inadequately protects sensitive information.",
        exploitability: "High",
        cvss: 7.5,
        remediation: "Encrypt all sensitive data at rest and in transit.",
        owasp: "A02:2021 - Cryptographic Failures"
      }
    };

    let normalizedType = 'unknown';
    for (const key of Object.keys(rules)) {
      if (type.includes(key) || key.includes(type.replace(' ', '_'))) {
        normalizedType = key;
        break;
      }
    }

    if (rules[normalizedType]) {
      return rules[normalizedType];
    }

    return {
      explanation: "Security vulnerability detected.",
      exploitability: "Medium",
      cvss: 5.0,
      remediation: "Apply appropriate security measures.",
      owasp: "Unknown"
    };
  },

  parseSafeJSON(text) {
    if (!text || typeof text !== 'string') return null;
    let rawText = text.trim();
    rawText = rawText.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/\s*```$/i, '').trim();
    try {
      return JSON.parse(rawText);
    } catch {
      const match = rawText.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
      if (match) {
        try {
          return JSON.parse(match[1]);
        } catch {}
      }
      return null;
    }
  },

  async analyzeFinding(finding) {
    if (this.mode === 'ollama') {
      try {
        const prompt = `Analyze this security finding: ${JSON.stringify(finding)}.
Respond ONLY with a JSON object containing EXACTLY these keys:
"explanation" (2 sentences, simple language),
"exploitability" (Low, Medium, High, or Critical),
"cvss" (number),
"remediation" (specific code-level fix),
"owasp" (string e.g. A03:2021 - Injection)`;
        
        const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
        const res = await axios.post(`${ollamaBaseUrl}/api/generate`, {
          model: this.model,
          prompt: prompt,
          stream: false,
          format: "json"
        }, { timeout: 10000 });
        
        const text = res.data.response;
        return this.parseSafeJSON(text) || this.ruleBasedAnalysis(finding);
      } catch (err) {
        return this.ruleBasedAnalysis(finding);
      }
    } else {
      return this.ruleBasedAnalysis(finding);
    }
  },

  async generateScanSummary(findings) {
    if (!findings || findings.length === 0) {
      return { summary: "No findings detected.", overallRisk: "Low", topIssues: [], priority: "None" };
    }

    let maxRisk = 'Low';
    const severities = findings.map(f => {
      const s = (f.severity || f.cvss_severity || 'low').toLowerCase();
      if (s === 'critical') return 4;
      if (s === 'high') return 3;
      if (s === 'medium') return 2;
      return 1;
    });
    
    const maxVal = Math.max(...severities);
    if (maxVal === 4) maxRisk = 'Critical';
    else if (maxVal === 3) maxRisk = 'High';
    else if (maxVal === 2) maxRisk = 'Medium';
    else maxRisk = 'Low';

    const topIssues = [...new Set(findings.map(f => f.type || f.vulnerability_name))].slice(0, 3);
    
    return {
      summary: `Scan completed with ${findings.length} findings.`,
      overallRisk: maxRisk,
      topIssues: topIssues,
      priority: maxRisk === 'Critical' || maxRisk === 'High' ? "Immediate Attention Required" : "Monitor"
    };
  },

  async checkFalsePositive(finding, responseSnippet) {
    if (this.mode === 'ollama') {
      try {
        const prompt = `Given this security finding: ${JSON.stringify(finding)}
And this HTTP response snippet: ${responseSnippet}
Is this finding a false positive? Respond ONLY with a JSON object containing:
"is_false_positive" (boolean), "confidence" (number 0-100), "reason" (string)`;

        const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
        const res = await axios.post(`${ollamaBaseUrl}/api/generate`, {
          model: this.model,
          prompt: prompt,
          stream: false,
          format: "json"
        }, { timeout: 10000 });
        
        return this.parseSafeJSON(res.data.response) || { is_false_positive: false, confidence: 50, reason: "Analysis failed to parse JSON." };
      } catch (err) {
        return { is_false_positive: false, confidence: 50, reason: "Analysis failed." };
      }
    } else {
      return { is_false_positive: false, confidence: 50, reason: "Rule-based engine cannot verify false positives." };
    }
  },

  /**
   * Analyze exploitation result and verify if the vulnerability is confirmed
   * 
   * @param {object} finding - vulnerability finding from scanner
   * @param {object} exploitResult - result from Metasploit exploitation
   * @returns {Promise<object>} AI verification result
   */
  async analyzeExploitResult(finding, exploitResult) {
    if (!exploitResult || !exploitResult.exploited) {
      return {
        confirmed: false,
        confidence: 0,
        evidence: 'Exploitation failed - vulnerability not confirmed',
        reasoning: 'Metasploit could not successfully exploit the target'
      };
    }

    if (this.mode === 'ollama') {
      try {
        const prompt = `You are a security expert analyzing exploitation results.

VULNERABILITY DETAILS:
- Type: ${finding.type}
- Target: ${finding.endpoint}
- Parameter: ${finding.parameter}
- Confidence (detection): ${finding.confidence || 'unknown'}

METASPLOIT EXPLOITATION RESULT:
- Module Used: ${exploitResult.moduleUsed}
- Success: ${exploitResult.success || exploitResult.exploited}
- Confidence: ${exploitResult.confidence}/100
- Evidence: ${exploitResult.evidence}
- Data Extracted: ${JSON.stringify(exploitResult.dataExtracted).substring(0, 500)}

QUESTION: Based on these exploitation results, is this a REAL, confirmed vulnerability?

RESPOND ONLY with a JSON object containing EXACTLY:
{
  "confirmed": boolean (true if real vulnerability, false if false positive),
  "confidence": number (0-100, your confidence level),
  "evidence": string (2-3 sentences explaining what proves/disproves the vulnerability),
  "reasoning": string (brief explanation of your conclusion)
}`;

        const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
        const res = await axios.post(`${ollamaBaseUrl}/api/generate`, {
          model: this.model,
          prompt: prompt,
          stream: false,
          format: "json"
        }, { timeout: 15000 });

        try {
          const parsed = this.parseSafeJSON(res.data.response);
          if (!parsed) throw new Error("Parsed result is empty");
          return {
            confirmed: parsed.confirmed === true,
            confidence: Math.min(100, Math.max(0, parsed.confidence || 0)),
            evidence: parsed.evidence || 'AI analysis completed',
            reasoning: parsed.reasoning || 'Exploitation confirmed vulnerability'
          };
        } catch (parseErr) {
          console.warn('[AutoAI] Failed to parse AI response:', parseErr.message);
          // Fallback: if exploitation was successful, assume confirmed
          return {
            confirmed: exploitResult.exploited,
            confidence: exploitResult.confidence || 75,
            evidence: exploitResult.evidence || 'Metasploit exploitation succeeded',
            reasoning: 'Exploitation result processed with fallback logic'
          };
        }
      } catch (err) {
        console.error('[AutoAI] analyzeExploitResult error:', err.message);
        // Fallback to rule-based analysis
        return this._ruleBasedExploitAnalysis(finding, exploitResult);
      }
    } else {
      // Rule-based analysis when Ollama is not available
      return this._ruleBasedExploitAnalysis(finding, exploitResult);
    }
  },

  /**
   * Rule-based analysis of exploit results (fallback)
   * @private
   */
  _ruleBasedExploitAnalysis(finding, exploitResult) {
    let confidence = Math.min(100, exploitResult.confidence || 75);
    let confirmed = exploitResult.exploited;

    // Boost confidence if data was extracted
    if (exploitResult.dataExtracted && Object.keys(exploitResult.dataExtracted).length > 0) {
      confidence = 100;
      confirmed = true;
    }

    // Reduce confidence if module failed but detection suggested something
    if (!confirmed && exploitResult.error) {
      confidence = Math.max(20, confidence - 30);
    }

    return {
      confirmed: confirmed,
      confidence: Math.round(confidence),
      evidence: exploitResult.evidence || (confirmed ? 'Metasploit exploitation successful' : 'Exploitation attempt completed'),
      reasoning: confirmed ? 
        'Metasploit successfully exploited the vulnerability and extracted proof' : 
        'Exploitation unsuccessful - vulnerability not confirmed by Metasploit'
    };
  }
};

module.exports = autoAI;