/**
 * WebSentinel-CS :: Remote Endpoint Security Auditor & SSRF Shield
 * Audits HTTP response headers against OWASP guidelines with strict SSRF filtering
 */

const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');

function isIpRestricted(ip) {
  const family = net.isIP(ip);
  if (!family) return false;

  if (family === 4) {
    const parts = ip.split('.').map(Number);
    // 0.0.0.0/8
    if (parts[0] === 0) return true;
    // Loopback: 127.0.0.0/8
    if (parts[0] === 127) return true;
    // Link-local / Cloud Metadata: 169.254.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return true;
    // RFC 1918: 10.0.0.0/8
    if (parts[0] === 10) return true;
    // RFC 1918: 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // RFC 1918: 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    // Carrier-grade NAT: 100.64.0.0/10
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    // Documentation / Reserved: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4 (multicast), 240.0.0.0/4 (reserved)
    if (parts[0] >= 224) return true;
    return false;
  }

  if (family === 6) {
    const lower = ip.toLowerCase();
    // Loopback ::1
    if (lower === '::1' || lower === '0000:0000:0000:0000:0000:0000:0000:0001') return true;
    // Unspecified ::
    if (lower === '::') return true;
    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if (lower.startsWith('::ffff:')) {
      const v4Part = lower.replace('::ffff:', '');
      return isIpRestricted(v4Part);
    }
    // Unique Local (fc00::/7)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    // Link-local (fe80::/10)
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
    return false;
  }

  return false;
}

function isHostAllowed(hostname, resolvedIps, allowlist = []) {
  if (!allowlist || allowlist.length === 0) return false;
  const lowerHost = hostname.toLowerCase();

  for (const item of allowlist) {
    const lowerItem = item.toLowerCase();
    if (lowerHost === lowerItem) return true;
    for (const ip of resolvedIps) {
      if (ip === lowerItem) return true;
    }
  }
  return false;
}

async function resolveAndValidateUrl(targetUrl, allowlist = []) {
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return { error: 'Solo se permiten protocolos http:// o https://' };
    }
  } catch (e) {
    return { error: 'Formato de URL inválido. Use http:// o https://' };
  }

  const hostname = parsedUrl.hostname;
  let resolvedIps = [];

  // Check if hostname is already a literal IP address
  if (net.isIP(hostname)) {
    resolvedIps = [hostname];
  } else {
    try {
      const records = await dns.lookup(hostname, { all: true });
      resolvedIps = records.map(r => r.address);
    } catch (err) {
      return { error: `Fallo de resolución DNS para el host ${hostname}: ${err.message}` };
    }
  }

  if (resolvedIps.length === 0) {
    return { error: `No se obtuvieron direcciones IP para el host ${hostname}` };
  }

  const allowed = isHostAllowed(hostname, resolvedIps, allowlist);

  if (!allowed) {
    for (const ip of resolvedIps) {
      if (isIpRestricted(ip)) {
        return {
          error: `SSRF bloqueado: Destino IP restringido (${ip}) no autorizado en SCAN_ALLOWLIST`
        };
      }
    }
  }

  return { parsedUrl, resolvedIps };
}

async function auditTargetUrl(targetUrl, allowlist = [], maxRedirects = 3, timeoutMs = 5000) {
  let currentUrl = targetUrl;
  let redirectsCount = 0;

  while (redirectsCount <= maxRedirects) {
    const validation = await resolveAndValidateUrl(currentUrl, allowlist);
    if (validation.error) {
      return { error: validation.error };
    }

    const { parsedUrl } = validation;
    const client = parsedUrl.protocol === 'https:' ? https : http;
    const startTime = Date.now();

    const result = await new Promise((resolve) => {
      let isSettled = false;

      const req = client.get(parsedUrl, { timeout: timeoutMs }, (res) => {
        // Handle HTTP Redirection
        if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
          req.destroy();
          const nextUrl = new URL(res.headers.location, currentUrl).toString();
          return resolve({ redirect: nextUrl });
        }

        const latencyMs = Date.now() - startTime;
        const headers = res.headers;
        let bytesCount = 0;

        res.on('data', (chunk) => {
          bytesCount += chunk.length;
          if (bytesCount > 524288) { // 512 KB
            req.destroy();
          }
        });

        res.on('end', () => {
          if (isSettled) return;
          isSettled = true;

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
            url: currentUrl,
            statusCode: res.statusCode,
            latencyMs,
            securityScore: score,
            headerChecks: headerStandards,
            missingHeadersCount: missing.length,
            rawHeaders: headers
          });
        });
      });

      req.on('error', (err) => {
        if (!isSettled) {
          isSettled = true;
          resolve({ error: `Fallo de conexión al destino: ${err.message}` });
        }
      });

      req.on('timeout', () => {
        req.destroy();
        if (!isSettled) {
          isSettled = true;
          resolve({ error: `Tiempo de espera excedido (> ${timeoutMs}ms)` });
        }
      });
    });

    if (result.redirect) {
      currentUrl = result.redirect;
      redirectsCount++;
      if (redirectsCount > maxRedirects) {
        return { error: 'Límite máximo de 3 redirecciones excedido' };
      }
      continue;
    }

    return result;
  }

  return { error: 'Demasiadas redirecciones' };
}

module.exports = {
  isIpRestricted,
  auditTargetUrl
};
