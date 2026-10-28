/**
 * WebSentinel-CS :: Remote Endpoint Security Auditor
 * Audits HTTP response headers against OWASP security guidelines using WHATWG URL
 */

const http = require('node:http');
const https = require('node:https');

async function auditTargetUrl(targetUrl, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return resolve({ error: 'Solo se permiten protocolos http:// o https://' });
      }
    } catch (e) {
      return resolve({ error: 'Formato de URL inválido. Use http:// o https://' });
    }

    const client = parsedUrl.protocol === 'https:' ? https : http;
    const startTime = Date.now();

    const req = client.get(parsedUrl, { timeout: timeoutMs }, (res) => {
      const latencyMs = Date.now() - startTime;
      const headers = res.headers;

      const headerStandards = {
        'content-security-policy': {
          header: 'Content-Security-Policy',
          present: Boolean(headers['content-security-policy']),
          impact: 'Mitigación de XSS, Clickjacking e inyección dinámica',
          severity: 'HIGH'
        },
        'x-frame-options': {
          header: 'X-Frame-Options',
          present: Boolean(headers['x-frame-options']),
          impact: 'Protección contra Clickjacking y anidamiento en frames',
          severity: 'MEDIUM'
        },
        'x-content-type-options': {
          header: 'X-Content-Type-Options',
          present: headers['x-content-type-options'] === 'nosniff',
          impact: 'Restricción de sniffing MIME indebido (nosniff)',
          severity: 'MEDIUM'
        },
        'strict-transport-security': {
          header: 'Strict-Transport-Security',
          present: Boolean(headers['strict-transport-security']),
          impact: 'Garantía obligatoria de transporte HTTPS cifrado (HSTS)',
          severity: parsedUrl.protocol === 'https:' ? 'HIGH' : 'LOW'
        },
        'referrer-policy': {
          header: 'Referrer-Policy',
          present: Boolean(headers['referrer-policy']),
          impact: 'Control de fuga de metadatos en peticiones salientes',
          severity: 'LOW'
        }
      };

      const missing = Object.values(headerStandards).filter(h => !h.present);
      const score = Math.max(10, 100 - (missing.length * 18));

      resolve({
        url: targetUrl,
        statusCode: res.statusCode,
        latencyMs,
        securityScore: score,
        headerChecks: headerStandards,
        missingHeadersCount: missing.length,
        rawHeaders: headers
      });
    });

    req.on('error', (err) => resolve({ error: `Fallo de conexión: ${err.message}` }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ error: `Tiempo de espera excedido (> ${timeoutMs}ms)` });
    });
  });
}

module.exports = { auditTargetUrl };
