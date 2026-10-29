/**
 * WebSentinel-CS :: Detection Signatures & Anomaly Scoring Engine (FASE 3 - P1)
 * OWASP Top 10 / CRS style scoring with multi-layer payload normalization,
 * ReDoS execution monitoring, and centralized rule definitions.
 */

const fs = require('node:fs');
const path = require('node:path');
const { normalizePayload } = require('./normalizer');
const { createLogger } = require('../logger');

const logger = createLogger(process.env.LOG_LEVEL || 'info');

// Load centralized signature catalogue from rules/signatures.json
const SIGNATURES_FILE_PATH = path.join(__dirname, '..', '..', 'rules', 'signatures.json');

let rawCatalogue = [];
try {
  const content = fs.readFileSync(SIGNATURES_FILE_PATH, 'utf8');
  rawCatalogue = JSON.parse(content);
} catch (err) {
  logger.error(`Error loading signatures from ${SIGNATURES_FILE_PATH}: ${err.message}`);
}

// Compile regular expressions with case-insensitivity flag once at boot
const COMPILED_SIGNATURES = rawCatalogue.map(sig => ({
  ...sig,
  compiledRegex: new RegExp(sig.regex, 'i')
}));

const SEVERITY_SCORES = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0
};

/**
 * Inspects a payload string against the compiled signatures and honeypot.
 * Normalizes input, monitors for ReDoS spikes (>50ms), and computes cumulative anomaly score.
 *
 * @param {string} inputString - Input string to inspect
 * @param {string} [honeypotValue] - Hidden honeypot field value
 * @param {number} [threshold=5] - Anomaly score threshold for blocking
 * @returns {object} Inspection result with anomaly score, status, action, and matched rules
 */
function inspectPayload(inputString, honeypotValue, threshold = 5) {
  const effectiveThreshold = typeof threshold === 'number' && threshold > 0 ? threshold : 5;
  const triggeredMap = new Map();

  // 1. Honeypot Bot Trap Evaluation
  if (honeypotValue && typeof honeypotValue === 'string' && honeypotValue.trim().length > 0) {
    triggeredMap.set('SIG-BOT-001', {
      id: 'SIG-BOT-001',
      ruleId: 'SIG-BOT-001',
      name: 'Automated Bot Trapped (Honeypot Non-Zero)',
      category: 'bot',
      severity: 'HIGH',
      cwe: 'CWE-799',
      score: 5,
      reason: 'Hidden bot field was populated by client.'
    });
  }

  // 2. Normalization Pipeline (URL, HTML entities, Unicode, SQL comments, whitespace)
  if (typeof inputString === 'string' && inputString.length > 0) {
    const { original, normalized } = normalizePayload(inputString);

    for (const sig of COMPILED_SIGNATURES) {
      let isMatch = false;

      // Measure regex evaluation duration for ReDoS safety
      const t0 = process.hrtime.bigint();
      try {
        if (sig.compiledRegex.test(original)) {
          isMatch = true;
        } else if (normalized !== original && sig.compiledRegex.test(normalized)) {
          isMatch = true;
        }
      } catch (regexErr) {
        logger.error(`Regex evaluation error in rule ${sig.id}: ${regexErr.message}`);
      }
      const t1 = process.hrtime.bigint();
      const durationMs = Number(t1 - t0) / 1e6;

      if (durationMs > 50) {
        logger.warn(`[WAF ReDoS Alert] Rule ${sig.id} took ${durationMs.toFixed(2)}ms to evaluate on payload`);
      }

      if (isMatch) {
        const score = typeof sig.score === 'number'
          ? sig.score
          : (SEVERITY_SCORES[sig.severity] || 1);

        triggeredMap.set(sig.id, {
          id: sig.id,
          ruleId: sig.id,
          name: sig.name,
          category: sig.category,
          severity: sig.severity,
          cwe: sig.cwe,
          score,
          description: sig.description,
          reason: `Matched detection signature ${sig.id} (${sig.name})`
        });
      }
    }
  }

  const triggeredRules = Array.from(triggeredMap.values());
  const scoreTotal = triggeredRules.reduce((sum, r) => sum + r.score, 0);

  let safe = true;
  let action = 'ALLOW';
  let status = 'SAFE';

  if (scoreTotal >= effectiveThreshold) {
    safe = false;
    action = 'BLOCK';
    status = 'BLOCKED';
  } else if (scoreTotal > 0) {
    safe = false;
    action = 'FLAG';
    status = 'SUSPICIOUS';
  }

  // Legacy threats representation for backwards compatibility
  const threats = triggeredRules.map(r => ({
    ruleId: r.id,
    name: r.name,
    severity: r.severity,
    cwe: r.cwe,
    score: r.score,
    reason: r.reason
  }));

  const result = {
    safe,
    action,
    status,
    scoreTotal,
    threshold: effectiveThreshold,
    threatCount: threats.length,
    threats,
    triggeredRules
  };

  // Provide array-like iterable interface for full backwards compatibility
  result[Symbol.iterator] = function* () {
    yield* threats;
  };
  Object.defineProperty(result, 'length', {
    get() {
      return threats.length;
    },
    enumerable: false
  });

  return result;
}

module.exports = {
  SIGNATURE_DATABASE: COMPILED_SIGNATURES,
  inspectPayload
};
