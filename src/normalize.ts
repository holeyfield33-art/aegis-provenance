// Text normalization for provenance matching. A model that decodes an
// obfuscated inert-span payload and retypes the plaintext (or folds
// homoglyphs when repeating text) breaks the literal byte-level link
// `argumentProvenanceMatch` relies on. These helpers recover that link by
// expanding a span's content into the plaintext forms a model could
// plausibly have produced from it, so substring matching still finds them.
//
// Every non-ASCII character this module cares about is built from an
// explicit numeric code point (never typed as a literal glyph in source) so
// the table is exact and can't be silently corrupted by editor/font/encoding
// transcription — which matters especially for the invisible-character set,
// since those code points are by definition impossible to visually diff.

function charFromCodePoint(codePoint: number): string {
  return String.fromCodePoint(codePoint);
}

function codePointRange(start: number, end: number): number[] {
  const out: number[] = [];
  for (let cp = start; cp <= end; cp += 1) {
    out.push(cp);
  }
  return out;
}

// Soft hyphen, zero-width space/non-joiner/joiner + LRM/RLM marks, bidi
// embedding/override controls, word joiner + invisible math operators, and
// the zero-width no-break space / byte-order mark.
const INVISIBLE_CODEPOINTS = [
  0x00ad,
  ...codePointRange(0x200b, 0x200f),
  ...codePointRange(0x202a, 0x202e),
  ...codePointRange(0x2060, 0x2064),
  0xfeff
];

const INVISIBLE_PATTERN = new RegExp(
  `[${INVISIBLE_CODEPOINTS.map((cp) => `\\u${cp.toString(16).padStart(4, '0')}`).join('')}]`,
  'g'
);

// Common Cyrillic/Greek homoglyphs used to evade literal Latin keyword
// matching (the standard IDN-homograph letter set). Not a full
// Unicode-confusables (TR39) skeleton implementation — covers the
// characters most often used in this style of evasion, not the entire
// confusables table.
const CONFUSABLE_CODEPOINT_PAIRS: Array<[number, string]> = [
  // Cyrillic lowercase -> Latin
  [0x0430, 'a'], [0x0435, 'e'], [0x043e, 'o'], [0x0440, 'p'], [0x0441, 'c'],
  [0x0445, 'x'], [0x0443, 'y'], [0x0456, 'i'], [0x0455, 's'], [0x0458, 'j'],
  // Cyrillic uppercase -> Latin
  [0x0410, 'A'], [0x0412, 'B'], [0x0415, 'E'], [0x041a, 'K'], [0x041c, 'M'],
  [0x041d, 'H'], [0x041e, 'O'], [0x0420, 'P'], [0x0421, 'C'], [0x0422, 'T'],
  [0x0425, 'X'], [0x0405, 'S'], [0x0408, 'J'],
  // Greek lowercase -> Latin
  [0x03b1, 'a'], [0x03bf, 'o'], [0x03c1, 'p'], [0x03bd, 'v'], [0x03c5, 'u'], [0x03ba, 'k'],
  // Greek uppercase -> Latin
  [0x0391, 'A'], [0x0392, 'B'], [0x0395, 'E'], [0x0396, 'Z'], [0x0397, 'H'],
  [0x0399, 'I'], [0x039a, 'K'], [0x039c, 'M'], [0x039d, 'N'], [0x039f, 'O'],
  [0x03a1, 'P'], [0x03a4, 'T'], [0x03a5, 'Y'], [0x03a7, 'X']
];

const CONFUSABLE_MAP: Record<string, string> = Object.fromEntries(
  CONFUSABLE_CODEPOINT_PAIRS.map(([codePoint, target]) => [charFromCodePoint(codePoint), target])
);

export function stripInvisible(text: string): string {
  return text.replace(INVISIBLE_PATTERN, '');
}

/** NFKC-normalizes (folds compatibility forms: full-width, ligatures, etc.)
 * and maps known Cyrillic/Greek homoglyphs to their Latin lookalikes. */
export function foldConfusables(text: string): string {
  const nfkc = text.normalize('NFKC');
  let out = '';
  for (const ch of nfkc) {
    out += CONFUSABLE_MAP[ch] ?? ch;
  }
  return out;
}

function isMostlyPrintable(text: string): boolean {
  if (text.length < 6) {
    return false;
  }
  const printable = text.match(/[\x20-\x7E]/g)?.length ?? 0;
  return printable / text.length >= 0.85;
}

function tryDecodeBase64(token: string): string | null {
  if (token.length < 20 || token.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(token)) {
    return null;
  }
  try {
    const decoded = Buffer.from(token, 'base64');
    const roundTrip = decoded.toString('base64').replace(/=+$/, '');
    if (roundTrip !== token.replace(/=+$/, '')) {
      return null;
    }
    const text = decoded.toString('utf8');
    return isMostlyPrintable(text) ? text : null;
  } catch {
    return null;
  }
}

function tryDecodeHex(token: string): string | null {
  if (token.length < 20 || token.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(token)) {
    return null;
  }
  try {
    const text = Buffer.from(token, 'hex').toString('utf8');
    return isMostlyPrintable(text) ? text : null;
  } catch {
    return null;
  }
}

export function rot13(text: string): string {
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
}

const BASE64_TOKEN = /[A-Za-z0-9+/]{20,}={0,2}/g;
const HEX_TOKEN = /(?:[0-9a-fA-F]{2}){10,}/g;

/**
 * Plausible plaintext decodings of `text`: itself, a whole-text ROT13 pass,
 * and the text with any base64- or hex-shaped tokens substituted by their
 * decoded form (kept in their surrounding context). Decodes are gated by a
 * round-trip check (base64) and a printable-output ratio so decoding never
 * turns ordinary prose into a spurious match.
 */
export function expandDecodedCandidates(text: string): string[] {
  const candidates = new Set<string>();
  candidates.add(text);
  candidates.add(rot13(text));

  const base64Decoded = text.replace(BASE64_TOKEN, (token) => tryDecodeBase64(token) ?? token);
  if (base64Decoded !== text) {
    candidates.add(base64Decoded);
  }

  const hexDecoded = text.replace(HEX_TOKEN, (token) => tryDecodeHex(token) ?? token);
  if (hexDecoded !== text) {
    candidates.add(hexDecoded);
  }

  return Array.from(candidates);
}

function collapseWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim().toLowerCase();
}

/**
 * Canonical form for provenance substring matching: strips invisible
 * characters, folds confusables/NFKC, then collapses whitespace and case.
 * A strict superset of plain whitespace/case normalization, so every case
 * that matched before still matches.
 */
export function normalizeMatchText(value: string): string {
  return collapseWhitespace(foldConfusables(stripInvisible(value)));
}

/** All normalized representations of `text` worth checking a provenance
 * match against: itself, plus decode/fold candidates. */
export function candidateRepresentations(text: string): string[] {
  const forms = new Set<string>();
  forms.add(normalizeMatchText(text));
  for (const decoded of expandDecodedCandidates(text)) {
    forms.add(normalizeMatchText(decoded));
  }
  return Array.from(forms);
}
