/**
 * WebSentinel-CS :: Detection Signatures Engine
 * Mapped to OWASP Top 10 and Common Weakness Enumeration (CWE)
 */

const SIGNATURE_DATABASE = [
  { id: 'SIG-SQLI-001', name: 'SQL Injection: Tautology / Boolean Bypass', regex: /('|\b)(OR|AND)\b.+(=|<|>).+/i, severity: 'CRITICAL', cwe: 'CWE-89' },
  { id: 'SIG-SQLI-002', name: 'SQL Injection: UNION-Based Exfiltration', regex: /\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b/i, severity: 'CRITICAL', cwe: 'CWE-89' },
  { id: 'SIG-SQLI-003', name: 'SQL Injection: Inline Comment / Stacked Query', regex: /(--|\/\*|;\s*(DROP|ALTER|INSERT|UPDATE|DELETE|EXEC)\b)/i, severity: 'CRITICAL', cwe: 'CWE-89' },
  { id: 'SIG-XSS-001',  name: 'Cross-Site Scripting: Explicit Tag Injection', regex: /<script\b[^>]*>([\s\S]*?)<\/script>/i, severity: 'HIGH', cwe: 'CWE-79' },
  { id: 'SIG-XSS-002',  name: 'Cross-Site Scripting: Inline Event Attribute', regex: /on(error|load|click|mouseover|submit|focus)\s*=/i, severity: 'HIGH', cwe: 'CWE-79' },
  { id: 'SIG-XSS-003',  name: 'Cross-Site Scripting: URI Scheme Invocation', regex: /javascript\s*:/i, severity: 'HIGH', cwe: 'CWE-79' },
  { id: 'SIG-PATH-001', name: 'Path Traversal: Directory Climb Sequence', regex: /(\.\.\/|\.\.\\)/i, severity: 'HIGH', cwe: 'CWE-22' },
  { id: 'SIG-PATH-002', name: 'LFI: Sensitive Configuration Probe', regex: /(\/etc\/passwd|win\.ini|boot\.ini|\.env|\.git)/i, severity: 'CRITICAL', cwe: 'CWE-22' }
];

function inspectPayload(inputString, honeypotValue) {
  const matches = [];

  if (honeypotValue && honeypotValue.trim().length > 0) {
    matches.push({
      ruleId: 'SIG-BOT-001',
      name: 'Automated Bot Trapped (Honeypot Non-Zero)',
      severity: 'HIGH',
      cwe: 'CWE-799',
      reason: 'Hidden bot field was populated by client.'
    });
  }

  if (typeof inputString === 'string') {
    for (const sig of SIGNATURE_DATABASE) {
      if (sig.regex.test(inputString)) {
        matches.push({
          ruleId: sig.id,
          name: sig.name,
          severity: sig.severity,
          cwe: sig.cwe,
          reason: `Matched detection signature ${sig.id}`
        });
      }
    }
  }

  return matches;
}

module.exports = {
  SIGNATURE_DATABASE,
  inspectPayload
};
