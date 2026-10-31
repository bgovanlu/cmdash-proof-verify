// SPDX-License-Identifier: Apache-2.0
/**
 * Output safety (spec section 9.5). Everything the verifier returns in a
 * check's `detail` or in the `summary`, and everything the CLI prints, is
 * printable ASCII. The verifier's own words are ASCII by construction; every
 * value that came from the input goes through the functions below.
 *
 * The trigger for all of this (vectors 58 and 59): a member NAME made of
 * ESC[2K, a carriage return and ESC[1;32m VALID repainted a terminal line as a
 * green "VALID" over an INVALID verdict. Escaping backslashes and double
 * quotes as well means a value can never close its own quotes and read as the
 * verifier's words (`x"; VALID - issued by ...`).
 */

const MAX_QUOTED_CODE_POINTS = 64;

/** Every code point outside U+0020..U+007E written as \u{hex} (lowercase); lone surrogates included. */
export function asciiEscape(s) {
  let out = '';
  for (const ch of String(s)) {
    const cp = ch.codePointAt(0);
    out += cp >= 0x20 && cp <= 0x7e ? ch : `\\u{${cp.toString(16)}}`;
  }
  return out;
}

/**
 * An unverified value, made safe to embed in a sentence: truncated to 64 code
 * points, backslashes and double quotes escaped, every non-printable code
 * point written \u{hex}, then quoted. Non-strings are described, not dumped.
 */
export function quote(value) {
  if (typeof value !== 'string') return describeValue(value);
  const cps = Array.from(value);
  const truncated = cps.length > MAX_QUOTED_CODE_POINTS;
  const head = truncated ? cps.slice(0, MAX_QUOTED_CODE_POINTS).join('') : value;
  const escaped = asciiEscape(head.replace(/\\/g, '\\\\').replace(/"/g, '\\"'));
  return `"${escaped}"${truncated ? ' (truncated)' : ''}`;
}

/**
 * A value whose shape is already constrained (it passed a schema pattern, or
 * it is verified text such as a statement), quoted and escaped the same way
 * but not truncated: an origin, a URL derived from one, a key id.
 */
export function quoteFull(value) {
  return `"${asciiEscape(String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"'))}"`;
}

/** A short, ASCII description of any JSON value, for "expected X, got Y" details. */
export function describeValue(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'nothing';
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'number')
    return Number.isFinite(value) ? String(value) : 'a non-finite number';
  if (typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return `an array of ${value.length}`;
  if (typeof value === 'object') return 'an object';
  return `a ${typeof value}`;
}
