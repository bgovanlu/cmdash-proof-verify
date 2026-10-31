// SPDX-License-Identifier: Apache-2.0
/**
 * The canonical form of spec section 3: the payload bytes a receipt signs.
 *
 * Admitted: objects (members sorted by name in UTF-16 code-unit order), arrays,
 * strings without a lone surrogate or a Unicode noncharacter, and integers in
 * -(2^53-1)..2^53-1 other than -0. Refused: true, false, null, floats,
 * non-finite numbers, -0, unsafe integers and anything that is not a plain
 * JSON value (a Date, a Map, a byte array, undefined, a bigint...). Depth is
 * at most 64: the top-level value has depth 0, a member or element its
 * container's depth plus one.
 *
 * Strings are serialized by ECMA-262 QuoteJSONString, written out here rather
 * than delegated to JSON.stringify so that the rule is visible: `"` and `\`
 * escaped, U+0008/9/A/C/D as \b \t \n \f \r, every other code point below
 * U+0020 as \u00XX with lowercase hex, everything else (U+007F, U+2028 and
 * non-ASCII included) as itself.
 */

/** A value outside the admitted subset; `rule` is one of the informative canonical.* rules. */
export class CanonicalError extends Error {
  constructor(rule, message) {
    super(message);
    this.name = 'CanonicalError';
    this.rule = rule;
  }
}

export const MAX_CANONICAL_DEPTH = 64;

/** Throws CanonicalError when `s` has a lone surrogate or a noncharacter (spec section 3, rule 5). */
function admitString(s, where) {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    let cp = c;
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d < 0xdc00 || d > 0xdfff)
        throw new CanonicalError('canonical.lone-surrogate', `a lone surrogate in ${where}`);
      cp = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonicalError('canonical.lone-surrogate', `a lone surrogate in ${where}`);
    }
    if ((cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe) {
      throw new CanonicalError(
        'canonical.noncharacter',
        `a Unicode noncharacter (U+${cp.toString(16).toUpperCase()}) in ${where}`,
      );
    }
  }
}

/** ECMA-262 QuoteJSONString for a string already admitted (so it has no lone surrogate). */
export function quoteJsonString(s) {
  let out = '"';
  let start = 0;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    let rep = null;
    if (c === 0x22) rep = '\\"';
    else if (c === 0x5c) rep = '\\\\';
    else if (c < 0x20) {
      if (c === 0x08) rep = '\\b';
      else if (c === 0x09) rep = '\\t';
      else if (c === 0x0a) rep = '\\n';
      else if (c === 0x0c) rep = '\\f';
      else if (c === 0x0d) rep = '\\r';
      else rep = `\\u00${c < 0x10 ? '0' : ''}${c.toString(16)}`;
    }
    if (rep !== null) {
      out += s.slice(start, i) + rep;
      start = i + 1;
    }
  }
  return `${out}${s.slice(start)}"`;
}

/** An own member, "__proto__" included; never an inherited one. */
export function hasOwn(o, k) {
  return Object.prototype.hasOwnProperty.call(o, k);
}

/** A JSON object as a parser makes it: not null, not an array, no prototype but Object's (or none). */
export function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function serialize(v, depth) {
  if (depth > MAX_CANONICAL_DEPTH)
    throw new CanonicalError('canonical.depth', `nesting deeper than ${MAX_CANONICAL_DEPTH}`);
  switch (typeof v) {
    case 'string':
      admitString(v, 'a string');
      return quoteJsonString(v);
    case 'number':
      if (!Number.isFinite(v))
        throw new CanonicalError('canonical.non-finite', 'a non-finite number');
      if (!Number.isInteger(v))
        throw new CanonicalError('canonical.float', 'a number with a fraction');
      if (Object.is(v, -0)) throw new CanonicalError('canonical.negative-zero', 'negative zero');
      if (!Number.isSafeInteger(v))
        throw new CanonicalError(
          'canonical.unsafe-integer',
          'an integer outside -(2^53-1)..2^53-1',
        );
      return String(v);
    case 'boolean':
      throw new CanonicalError('canonical.boolean', 'a boolean');
    case 'object': {
      if (v === null) throw new CanonicalError('canonical.null', 'null');
      if (Array.isArray(v)) {
        const parts = [];
        for (let i = 0; i < v.length; i += 1) parts.push(serialize(v[i], depth + 1));
        return `[${parts.join(',')}]`;
      }
      if (!isPlainObject(v))
        throw new CanonicalError(
          'canonical.type',
          'a value that is not plain JSON (an object with a prototype)',
        );
      const names = Object.keys(v);
      for (const name of names) admitString(name, 'a member name');
      // Array.prototype.sort's default order compares UTF-16 code units (spec section 3, rule 6).
      names.sort();
      const parts = [];
      for (const name of names)
        parts.push(`${quoteJsonString(name)}:${serialize(v[name], depth + 1)}`);
      return `{${parts.join(',')}}`;
    }
    default:
      throw new CanonicalError('canonical.type', `a value of type ${typeof v}`);
  }
}

/** The canonical serialization of a plain JSON value (a string; encode it as UTF-8 for the bytes). */
export function canonicalize(value) {
  return serialize(value, 0);
}
