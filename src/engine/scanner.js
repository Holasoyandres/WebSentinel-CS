/**
 * WebSentinel-CS :: Remote Endpoint Security Auditor & SSRF Shield
 * Audits HTTP response headers against OWASP guidelines with strict CIDR evaluation and DNS rebinding defense
 */

const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');

function createRestrictedBlockList() {
  const bl = new net.BlockList();
  // IPv4 Private & Restricted
  bl.addSubnet('0.0.0.0', 8, 'ipv4');          // Current network
  bl.addSubnet('10.0.0.0', 8, 'ipv4');         // RFC 1918 Private
  bl.addSubnet('100.64.0.0', 10, 'ipv4');      // Carrier-grade NAT
  bl.addSubnet('127.0.0.0', 8, 'ipv4');        // Loopback
  bl.addSubnet('169.254.0.0', 16, 'ipv4');     // Link-local / Cloud Metadata
  bl.addSubnet('172.16.0.0', 12, 'ipv4');      // RFC 1918 Private
  bl.addSubnet('192.0.2.0', 24, 'ipv4');       // Documentation TEST-NET-1
  bl.addSubnet('192.168.0.0', 16, 'ipv4');     // RFC 1918 Private
  bl.addSubnet('198.51.100.0', 24, 'ipv4');    // Documentation TEST-NET-2
  bl.addSubnet('203.0.113.0', 24, 'ipv4');     // Documentation TEST-NET-3
  bl.addSubnet('224.0.0.0', 4, 'ipv4');        // Multicast
  bl.addSubnet('240.0.0.0', 4, 'ipv4');        // Reserved

  // IPv6 Private & Restricted
  bl.addAddress('::', 'ipv6');                 // Unspecified
  bl.addAddress('::1', 'ipv6');                // Loopback
  bl.addSubnet('fc00::', 7, 'ipv6');           // Unique Local Address (ULA)
  bl.addSubnet('fe80::', 10, 'ipv6');          // Link-local
  bl.addSubnet('ff00::', 8, 'ipv6');           // Multicast
  return bl;
}

const RESTRICTED_BLOCKLIST = createRestrictedBlockList();

function parseAllowlist(allowlist = []) {
  const bl = new net.BlockList();
  const hostnames = new Set();
  let entriesCount = 0;

  for (const item of allowlist) {
    const trimmed = String(item).trim();
    if (!trimmed) continue;
    entriesCount++;

    if (trimmed.includes('/')) {
      const [ip, prefix] = trimmed.split('/');
      const family = net.isIP(ip);
      if (family === 4) bl.addSubnet(ip, parseInt(prefix, 10), 'ipv4');
      else if (family === 6) bl.addSubnet(ip, parseInt(prefix, 10), 'ipv6');
    } else {
      const family = net.isIP(trimmed);
      if (family === 4) bl.addAddress(trimmed, 'ipv4');
      else if (family === 6) bl.addAddress(trimmed, 'ipv6');
      else hostnames.add(trimmed.toLowerCase());
    }
  }

  return { blockList: bl, hostnames, entriesCount };
}

function isIpRestricted(ip) {
  const family = net.isIP(ip);
  if (!family) return false;
  const familyType = family === 6 ? 'ipv6' : 'ipv4';
  try {
    return RESTRICTED_BLOCKLIST.check(ip, familyType);
  } catch (_) {
    return false;
  }
}

function isIpAllowed(ip, parsedAllowlist) {
  if (parsedAllowlist.entriesCount === 0) return false;
  const family = net.isIP(ip);
  if (!family) return false;
  const familyType = family === 6 ? 'ipv6' : 'ipv4';
  try {
    return parsedAllowlist.blockList.check(ip, familyType);
  } catch (_) {
    return false;
  }
}

async function resolveAndValidateUrl(targetUrl, rawAllowlist = []) {
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
  const parsedAllow = parseAllowlist(rawAllowlist);

  let resolvedIps = [];

  // Check if hostname is already a literal IP
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

  const hostIsExplicitlyAllowed = parsedAllow.hostnames.has(hostname.toLowerCase());

  for (const ip of resolvedIps) {
    const ipIsAllowed = isIpAllowed(ip, parsedAllow);
    if (!hostIsExplicitlyAllowed && !ipIsAllowed) {
      if (isIpRestricted(ip)) {
        return {
          error: `SSRF bloqueado: Destino IP restringido (${ip}) no autorizado en SCAN_ALLOWLIST`
        };
      }
    }
  }

  return { parsedUrl, pinnedIp: resolvedIps[0] };
}

async function auditTargetUrl(targetUrl, allowlist = [], maxRedirects = 3, timeoutMs = 5000) {
  let currentUrl = targetUrl;
  let redirectsCount = 0;

  while (redirectsCount <= maxRedirects) {
    const validation = await resolveAndValidateUrl(currentUrl, allowlist);
    if (validation.error) {
      return { error: validation.error };
    }

    const { parsedUrl, pinnedIp } = validation;
    const client = parsedUrl.protocol === 'https:' ? https : http;
    const startTime = Date.now();
    const pinnedFamily = net.isIP(pinnedIp);

    const requestOptions = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      timeout: timeoutMs,
      headers: {
        Host: parsedUrl.host,
        'User-Agent': 'WebSentinel-Audit-Engine/1.3.0',
        Accept: '*/*'
      },
      servername: parsedUrl.hostname, // TLS SNI
      // Anti-DNS Rebinding: Pin connection directly to pre-validated IP
      lookup: (host, opts, cb) => {
        if (typeof opts === 'function') {
          cb = opts;
          opts = {};
        }
        const familyNum = pinnedFamily === 6 ? 6 : 4;
        if (opts && opts.all) {
          cb(null, [{ address: pinnedIp, family: familyNum }]);
        } else {
          cb(null, pinnedIp, familyNum);
        }
      }
    };

    const result = await new Promise((resolve) => {
      let isSettled = false;

      const req = client.get(requestOptions, (res) => {
        // Handle HTTP Redirections with re-validation
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
