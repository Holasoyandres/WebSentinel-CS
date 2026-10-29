/**
 * WebSentinel-CS :: Payload Normalization Pipeline (FASE 3 - P1)
 * Multi-layer canonicalization and decoding engine to prevent WAF evasion techniques.
 * Enforces ReDoS safe boundary by truncating payloads to 16 KB (16,384 characters).
 */

const MAX_INSPECTION_LENGTH = 16384; // 16 KB boundary

/**
 * Safely decodes URL percent-encoding without crashing on invalid or truncated byte sequences.
 */
function safeDecodeUri(str) {
  try {
    return decodeURIComponent(str.replace(/\+/g, ' '));
  } catch (_) {
    // Robust fallback: decode valid %xx hex sequences individually
    return str.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
      try {
        const charCode = parseInt(hex, 16);
        return String.fromCharCode(charCode);
      } catch {
        return match;
      }
    });
  }
}

/**
 * Recursively decodes URL encoding up to maxPasses (default 3) to counter double/triple encoding.
 */
function recursiveUrlDecode(str, maxPasses = 3) {
  let current = str;
  for (let i = 0; i < maxPasses; i++) {
    if (!current.includes('%')) break;
    const decoded = safeDecodeUri(current);
    if (decoded === current) break;
    current = decoded;
  }
  return current;
}

/**
 * Decodes standard named and numeric (decimal and hexadecimal) HTML entities.
 */
function decodeHtmlEntities(str) {
  if (!str.includes('&')) return str;

  // 1. Numeric Hexadecimal (e.g. &#x27; or &#x3C;)
  let res = str.replace(/&#x([0-9a-fA-F]{1,6});?/gi, (_, hex) => {
    try {
      const code = parseInt(hex, 16);
      return String.fromCodePoint(code);
    } catch {
      return _;
    }
  });

  // 2. Numeric Decimal (e.g. &#39; or &#60;)
  res = res.replace(/&#([0-9]{1,7});?/g, (_, dec) => {
    try {
      const code = parseInt(dec, 10);
      return String.fromCodePoint(code);
    } catch {
      return _;
    }
  });

  // 3. Common Named HTML Entities
  const NAMED_ENTITIES = {
    '&quot;': '"',
    '&apos;': "'",
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&nbsp;': ' '
  };

  res = res.replace(/&(?:quot|apos|amp|lt|gt|nbsp);?/gi, (match) => {
    const lower = match.toLowerCase();
    const withSemi = lower.endsWith(';') ? lower : lower + ';';
    return NAMED_ENTITIES[withSemi] || match;
  });

  return res;
}

/**
 * Main normalization pipeline function.
 * Returns both the original string and the fully canonicalized representation.
 *
 * @param {string} input - Raw user or request payload
 * @returns {{ original: string, normalized: string }}
 */
function normalizePayload(input) {
  if (typeof input !== 'string') {
    const empty = typeof input === 'undefined' || input === null ? '' : String(input);
    return { original: empty, normalized: empty };
  }

  // 0. Enforce ReDoS Safe Length Boundary (16 KB)
  const boundedInput = input.length > MAX_INSPECTION_LENGTH
    ? input.slice(0, MAX_INSPECTION_LENGTH)
    : input;

  // 1. Recursive URL Decoding (up to 3 passes)
  let processed = recursiveUrlDecode(boundedInput, 3);

  // 2. HTML Entity Decoding (named & numeric)
  processed = decodeHtmlEntities(processed);

  // 3. Unicode NFKC Normalization & Null Byte Stripping
  try {
    processed = processed.normalize('NFKC');
  } catch (_) {
    // If runtime normalization fails on rare code points, proceed gracefully
  }
  processed = processed.replace(/[\0\u0000]/g, '');

  // 4. Strip Inline SQL Comments (/* ... */)
  processed = processed.replace(/\/\*[\s\S]*?\*\//g, ' ');

  // 5. Collapse Consecutive Whitespace
  processed = processed.replace(/\s+/g, ' ').trim();

  return {
    original: boundedInput,
    normalized: processed
  };
}

module.exports = {
  MAX_INSPECTION_LENGTH,
  normalizePayload
};
