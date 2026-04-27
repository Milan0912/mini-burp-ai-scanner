'use strict';

/**
 * Industry-Level Attack Orchestrator v4 (Real-World Detection Edition)
 * ====================================================================
 * Professional-grade control, explaining every cognitive step.
 * Implements loose 3-stage validation logic.
 */

const AttackEngine = require('./AttackEngine');
const ValidationEngine = require('./ValidationEngine');
const ExploitEngine = require('./ExploitEngine');
const AppModel = require('./AppModel');
const reportGenerator = require('./reportGenerator');
const { VECTORS } = require('./vulnerabilityVectors');

class AttackOrchestrator {
    constructor(io, mode = 'balanced') {
        this.io = io;
        this.mode = mode; 
        this.intelLog = [];
    }

    logIntel(reqId, data) {
        const entry = {
            timestamp: Date.now(),
            reqId,
            ...data
        };
        this.intelLog.push(entry);
        if (this.io) this.io.emit('intel:log', entry);
        console.log(`[Intel] [${data.phase}] ${data.message || data.reason || data.payload}`);
    }

    async safeExecute(reqCtx, mutation = null) {
        let retries = 0;
        while (retries < 2) { 
            const res = await AttackEngine.execute(reqCtx, mutation);
            if (res) return res;
            retries++;
            await new Promise(r => setTimeout(r, 1000));
        }
        return null;
    }

    getTier(score) {
        if (score >= 90) return 'VERIFIED';
        if (score >= 70) return 'HIGH';
        if (score >= 50) return 'SUSPICIOUS';
        return 'IGNORE';
    }

    async orchestrate(reqId, reqCtx, inputs) {
        this.logIntel(reqId, { phase: 'OBSERVE', reason: 'Capturing baseline and modeling endpoint structure.' });
        AppModel.addEndpoint(reqCtx.url, reqCtx.method, inputs);

        this.logIntel(reqId, { phase: 'OBSERVE', reason: 'Capturing baseline...' });
        const baseline = await this.safeExecute(reqCtx);
        if (!baseline) {
            this.logIntel(reqId, { phase: 'FAIL', message: 'Failed to capture baseline. Aborting.' });
            return;
        }
        baseline.avgTime = baseline.elapsed;

        for (const input of inputs) {
            for (const [vectorName, vectorData] of Object.entries(VECTORS)) {
                // Test 5-10 payloads per parameter
                const payloadsToTest = vectorData.payloads.slice(0, 10);
                
                for (const payload of payloadsToTest) {
                    const task = { vector: vectorName, payload };
                    
                    this.logIntel(reqId, { phase: 'ATTACK', message: `Injecting ${task.vector} into ${input.param}: ${payload}`, payload });
                    const res1 = await this.safeExecute(reqCtx, { ...input, payload: task.payload });
                    
                    if (!res1) { 
                        this.logIntel(reqId, { phase: 'FAIL', message: `Attack failed/timeout for ${task.vector}` });
                        continue; 
                    }

                    // 1. Detection (LOOSE)
                    const diffLength = Math.abs(res1.length - baseline.length);
                    this.logIntel(reqId, { phase: 'COMPARE', message: `Status: ${res1.status}, Diff: ${diffLength} bytes`, diff: diffLength });

                    const validation = ValidationEngine.validate(baseline, res1, task);
                    
                    if (validation.isValid) {
                        this.logIntel(reqId, { phase: 'SUSPICIOUS', message: `Anomaly detected. Signals: ${validation.signals.join(', ')}` });
                        
                        // 2. Validation (REQUIRED) - Consistency check (3 times)
                        let consistencyRes2 = await this.safeExecute(reqCtx, { ...input, payload: task.payload });
                        let consistencyRes3 = await this.safeExecute(reqCtx, { ...input, payload: task.payload });
                        
                        let isConsistent = false;
                        if (consistencyRes2 && consistencyRes3 && 
                            ValidationEngine.verifyConsistency(res1, consistencyRes2) && 
                            ValidationEngine.verifyConsistency(res1, consistencyRes3)) {
                            
                            isConsistent = true;
                            validation.score += 20;
                            validation.signals.push('Highly Consistent (3x runs)');
                            this.logIntel(reqId, { phase: 'CONSISTENT', message: `Behavior highly consistent (3x). Bonus +20 applied.` });

                            // Control payloads
                            let controlPassed = true;
                            if (task.vector === 'sqli') {
                                const falsePayload = payload.replace(/'1'='1|1=1|'a'='a|"a"="a/g, "1=2");
                                if (falsePayload !== payload) {
                                    const resFalse = await this.safeExecute(reqCtx, { ...input, payload: falsePayload });
                                    if (resFalse) {
                                        const trueFalseDiff = Math.abs(res1.length - resFalse.length);
                                        if (trueFalseDiff > 15 || res1.status !== resFalse.status) {
                                            validation.score += 30; // Boolean diff confirmed
                                            validation.signals.push('Boolean Diff Confirmed (+30)');
                                            this.logIntel(reqId, { phase: 'CONTROL_PASSED', message: `Control payload diff confirmed. Bonus +30 applied.` });
                                        } else {
                                            controlPassed = false; // False positive, noise
                                        }
                                    }
                                }
                            }

                            if (controlPassed) {
                                // 3. Exploit (CONFIRMATION)
                                const exploit = await ExploitEngine.attemptExploit({ reqCtx, input }, task.vector, task.payload, baseline);
                                
                                const finalConfidence = Math.max(validation.score, exploit.confidence || 0);

                                if (exploit.success || finalConfidence >= 50) {
                                    const tier = exploit.success ? 'VERIFIED' : this.getTier(finalConfidence);

                                    this.logIntel(reqId, { phase: 'FINDING', message: `Confirmed ${task.vector} with ${tier} confidence.` });
                                    
                                    reportGenerator.addFinding({
                                        reqId,
                                        type:             task.vector.toUpperCase(),
                                        param:            input.param,        // ← correct field name
                                        payload:          task.payload,
                                        confidence_score: finalConfidence,
                                        confidence_tier:  tier,
                                        severity:         vectorData.severity,
                                        evidence:         exploit.proof || validation.signals.join(', '),
                                        proof:            exploit.data,
                                        url:              reqCtx.url,         // ← correct field name
                                        method:           reqCtx.method,
                                        reproduction_steps: [                 // ← correct field name
                                            `1. Open Proxy/Repeater and target ${reqCtx.url}`,
                                            `2. Set HTTP Method to ${reqCtx.method}`,
                                            `3. Inject payload into parameter '${input.param}': ${task.payload}`,
                                            `4. Observe response status ${res1.status} and length ${res1.length}`,
                                            `5. Compare with baseline: status ${baseline.status}, length ${baseline.length}`,
                                            `6. Indicator: ${exploit.proof || validation.signals.join(', ')}`
                                        ],
                                        raw_request:  `[${reqCtx.method}] ${reqCtx.url}\nPayload: ${task.payload}`,
                                        raw_response: `[Status: ${res1.status}]\n${(res1.body || '').slice(0, 500)}`
                                    });
                                }
                            } else {
                                this.logIntel(reqId, { phase: 'CONTROL_FAILED', message: `Control payload behaved same as attack payload. False positive.` });
                            }
                        } else {
                            this.logIntel(reqId, { phase: 'INCONSISTENT', message: 'Inconsistent behavior detected (Dynamic Noise Filtered).' });
                        }
                    }
                }
            }
        }
        this.logIntel(reqId, { phase: 'DONE', message: 'Finished testing all vectors for endpoint.' });
    }
}

module.exports = AttackOrchestrator;
