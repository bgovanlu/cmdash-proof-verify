// SPDX-License-Identifier: Apache-2.0
/**
 * The strict JSON reader of spec section 3.4, used for every document the
 * verifier reads: the receipt file, a key document, a log key document, a
 * supplied log section, an evidence opening and an evidence item.
 *
 *   - bytes are decoded as UTF-8 with a FATAL decoder that keeps a byte-order
 *     mark (so the parser refuses it);
 *   - the text is RFC 8259 JSON, read by a parser that refuses a duplicate
 *     member name at any depth: JSON.parse keeps the last one, other parsers
 *     keep the first, so one file would otherwise be two receipts (vector 77);
 *   - trailing content, a byte-order mark and nesting deeper than 64 are
 *     refused (the top-level value has depth 0, a member or element its
 *     container's depth plus one; a value deeper than 64 is refused);
 *   - a file larger than its limit is refused before it is parsed.
 *
 * The parser otherwise yields exactly what JSON.parse yields: plain objects
 * whose members are own data properties ("__proto__" included), arrays,
 * strings (an escaped lone surrogate is kept, as JSON.parse keeps it) and
 * numbers converted by Number(), -0 included.
 */
import { decodeUtf8Fatal, isUint8Array, isWellFormedUtf16, utf8Length } from './bytes.mjs';
import { quote } from './escape.mjs';

/** File limits in bytes (spec section 3.4). */
export const JSON_LIMITS = Object.freeze({
  receipt: 65536,
  keyDocument: 1048576,
  logKeyDocument: 1048576,
  logSection: 65536,
  opening: 65536,
  item: 65536,
});

export const MAX_JSON_DEPTH = 64;

/** A document the verifier refused to read; `rule` is a spec json.* rule. */
export class StrictJsonError extends Error {
  constructor(rule, message) {
    super(message);
    this.name = 'StrictJsonError';
    this.rule = rule;
  }
}

/**
 * Reads one document: `input` is its bytes (Uint8Array) or its text. Throws
 * StrictJsonError (json.too-large, json.syntax, json.duplicate-member).
 */
export function readJsonDocument(input, limit) {
  let text;
  if (isUint8Array(input)) {
    if (input.length > limit)
      throw new StrictJsonError(
        'json.too-large',
        `the file is ${input.length} bytes; the limit is ${limit}`,
      );
    text = decodeUtf8Fatal(input);
    if (text === null) throw new StrictJsonError('json.syntax', 'the file is not valid UTF-8');
  } else if (typeof input === 'string') {
    // A string with a lone surrogate is the decoding of no UTF-8 byte string.
    if (!isWellFormedUtf16(input))
      throw new StrictJsonError(
        'json.syntax',
        'the text is not valid UTF-8 (it contains a lone surrogate)',
      );
    const size = utf8Length(input);
    if (size > limit)
      throw new StrictJsonError(
        'json.too-large',
        `the file is ${size} bytes; the limit is ${limit}`,
      );
    text = input;
  } else {
    throw new StrictJsonError('json.syntax', 'not a JSON document (neither bytes nor text)');
  }
  return parseStrictJson(text);
}

const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/** RFC 8259 JSON, no duplicate member names, no BOM, no trailing content, depth at most 64. */
export function parseStrictJson(text) {
  if (typeof text !== 'string') throw new StrictJsonError('json.syntax', 'not a JSON text');
  let pos = 0;
  const n = text.length;

  const fail = (what) => {
    throw new StrictJsonError('json.syntax', `${what} at offset ${pos}`);
  };
  const skipWs = () => {
    while (pos < n) {
      const c = text.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos += 1;
      else break;
    }
  };

  const parseString = () => {
    // text[pos] is the opening quote
    pos += 1;
    let out = '';
    let start = pos;
    for (;;) {
      if (pos >= n) fail('unterminated string');
      const c = text.charCodeAt(pos);
      if (c === 0x22) {
        out += text.slice(start, pos);
        pos += 1;
        return out;
      }
      if (c === 0x5c) {
        out += text.slice(start, pos);
        pos += 1;
        if (pos >= n) fail('unterminated escape');
        const e = text[pos];
        if (e === '"') out += '"';
        else if (e === '\\') out += '\\';
        else if (e === '/') out += '/';
        else if (e === 'b') out += '\b';
        else if (e === 'f') out += '\f';
        else if (e === 'n') out += '\n';
        else if (e === 'r') out += '\r';
        else if (e === 't') out += '\t';
        else if (e === 'u') {
          const h = text.slice(pos + 1, pos + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) fail('bad \\u escape');
          out += String.fromCharCode(parseInt(h, 16));
          pos += 4;
        } else fail('bad escape');
        pos += 1;
        start = pos;
        continue;
      }
      if (c < 0x20) fail('unescaped control character in a string');
      pos += 1;
    }
  };

  const parseValue = (depth) => {
    if (depth > MAX_JSON_DEPTH)
      throw new StrictJsonError(
        'json.syntax',
        `nesting deeper than ${MAX_JSON_DEPTH} at offset ${pos}`,
      );
    if (pos >= n) fail('unexpected end of input');
    const c = text[pos];
    if (c === '{') {
      pos += 1;
      const obj = {};
      const seen = new Set();
      skipWs();
      if (text[pos] === '}') {
        pos += 1;
        return obj;
      }
      for (;;) {
        if (text[pos] !== '"') fail('expected a member name');
        const name = parseString();
        if (seen.has(name)) {
          throw new StrictJsonError(
            'json.duplicate-member',
            `duplicate member name ${quote(name)} at depth ${depth + 1}`,
          );
        }
        seen.add(name);
        skipWs();
        if (text[pos] !== ':') fail('expected ":"');
        pos += 1;
        skipWs();
        const value = parseValue(depth + 1);
        // An own data property even for "__proto__", exactly as JSON.parse creates it.
        Object.defineProperty(obj, name, {
          value,
          writable: true,
          enumerable: true,
          configurable: true,
        });
        skipWs();
        if (text[pos] === ',') {
          pos += 1;
          skipWs();
          continue;
        }
        if (text[pos] === '}') {
          pos += 1;
          return obj;
        }
        fail('expected "," or "}"');
      }
    }
    if (c === '[') {
      pos += 1;
      const arr = [];
      skipWs();
      if (text[pos] === ']') {
        pos += 1;
        return arr;
      }
      for (;;) {
        arr.push(parseValue(depth + 1));
        skipWs();
        if (text[pos] === ',') {
          pos += 1;
          skipWs();
          continue;
        }
        if (text[pos] === ']') {
          pos += 1;
          return arr;
        }
        fail('expected "," or "]"');
      }
    }
    if (c === '"') return parseString();
    if (c === 't') {
      if (text.startsWith('true', pos)) {
        pos += 4;
        return true;
      }
      fail('bad literal');
    }
    if (c === 'f') {
      if (text.startsWith('false', pos)) {
        pos += 5;
        return false;
      }
      fail('bad literal');
    }
    if (c === 'n') {
      if (text.startsWith('null', pos)) {
        pos += 4;
        return null;
      }
      fail('bad literal');
    }
    if (c === '-' || (c >= '0' && c <= '9')) {
      NUMBER_RE.lastIndex = pos;
      const m = NUMBER_RE.exec(text);
      if (m === null) fail('bad number');
      pos += m[0].length;
      return Number(m[0]);
    }
    return fail(c === '\u{feff}' ? 'a byte-order mark' : 'unexpected character');
  };

  skipWs();
  const value = parseValue(0);
  skipWs();
  if (pos !== n) fail('trailing content');
  return value;
}
