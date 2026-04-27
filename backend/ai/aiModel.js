'use strict';

/**
 * aiModel.js — Thin facade over ollamaClient
 * ==========================================
 * All AI logic now lives in ollamaClient.js.
 * This module re-exports the named functions so existing imports stay unbroken.
 */

const ollamaClient = require('./ollamaClient');

module.exports = {
    decideInitialStrategy: ollamaClient.decideStrategy,
    analyzeAttackResult:   ollamaClient.analyzeAttackResult,
    nextStrategy:          ollamaClient.nextStrategy,
    generateReportDetails: ollamaClient.generateReportDetails,
    generateAIResponse:    ollamaClient.generateAIResponse,
};
