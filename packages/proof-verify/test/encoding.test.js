// SPDX-License-Identifier: Apache-2.0
/**
 * The byte-level rules: the strict JSON reader (spec section 3.4), the
 * canonical form (section 3), strict base64url / base64, and UTF-8.
 */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  decodeBase64Std,
  decodeBase64Url,
  encodeBase64Std,
  encodeBase64Url,
  fromHex,
  isWellFormedUtf16,
  toHex,
  utf8Length,
} from '../lib/bytes.mjs';
import { CanonicalError, canonicalize, quoteJsonString } from '../lib/canonical.mjs';
import { asciiEscape, describeValue, quote, quoteFull } from '../lib/escape.mjs';
import { JSON_LIMITS, StrictJsonError, parseStrictJson, readJsonDocument } from '../lib/json.mjs';
import { loadVectors } from './helpers.js';

const vectors = loadVectors();
const rejects = (fn, rule, label) => assert.throws(fn, (e) => e.rule === rule, label);

describe('the strict JSON reader (spec section 3.4)', () => {
  test('reads exactly what JSON.parse reads: values, escapes, numbers, -0, __proto__ as an own member', () => {
    const samples = [
      '{"a":[1,-2,3.5,1e3,-0,true,false,null,"x\\n\\u00e9\\ud83d\\ude00"],"b":{"c":{}},"__proto__":{"p":1}}',
      ' \n\t[ ] ',
      '"\\/\\b\\f\\r\\t\\"\\\\"',
      '-0.0e+10',
      '"\\ud800"',
      '1E400',
      ...vectors
        .filter((v) => typeof v.input.receipt !== 'string')
        .map((v) => JSON.stringify(v.input.receipt)),
    ];
    for (const s of samples) assert.deepEqual(parseStrictJson(s), JSON.parse(s), s.slice(0, 40));
    const proto = parseStrictJson('{"__proto__":1}');
    assert.ok(Object.prototype.hasOwnProperty.call(proto, '__proto__'));
    assert.equal(Object.getPrototypeOf(proto), Object.prototype);
    assert.ok(Object.is(parseStrictJson('-0'), -0));
  });

  test('refuses a duplicate member name at any depth, even when spelled with an escape', () => {
    for (const s of [
      '{"a":1,"a":1}',
      '{"x":{"a":1,"b":2,"a":3}}',
      '[{"k":1},{"k":2,"k":2}]',
      '{"a":1,"\\u0061":2}',
    ]) {
      rejects(() => parseStrictJson(s), 'json.duplicate-member', s);
    }
  });

  test('refuses what JSON.parse refuses, a byte-order mark and trailing content', () => {
    for (const s of [
      '\u{feff}{}',
      '{} x',
      '{"a":1,}',
      '[01]',
      '"\t"',
      '{"a" 1}',
      "{'a':1}",
      '',
      '+1',
      '"\\x"',
      '[1',
      '{"a":1',
      '"\\u12g4"',
      'tru',
      '[1,]',
      '{,}',
      '1.',
      '-',
      '.5',
      'NaN',
    ]) {
      rejects(() => parseStrictJson(s), 'json.syntax', JSON.stringify(s));
      assert.throws(() => JSON.parse(s), undefined, `JSON.parse refuses ${JSON.stringify(s)} too`);
    }
  });

  test('nesting: a value at depth 64 is read, one at depth 65 is refused', () => {
    assert.deepEqual(
      parseStrictJson(`${'['.repeat(64)}1${']'.repeat(64)}`),
      JSON.parse(`${'['.repeat(64)}1${']'.repeat(64)}`),
    );
    assert.ok(parseStrictJson(`${'['.repeat(65)}${']'.repeat(65)}`));
    rejects(() => parseStrictJson(`${'['.repeat(65)}1${']'.repeat(65)}`), 'json.syntax');
    rejects(() => parseStrictJson(`${'['.repeat(66)}${']'.repeat(66)}`), 'json.syntax');
    rejects(() => parseStrictJson(`${'{"a":'.repeat(65)}1${'}'.repeat(65)}`), 'json.syntax');
  });

  test('a file: size first, then fatal UTF-8 (a stray byte or a BOM is refused, never replaced)', () => {
    const text = '{"a":"\u{e9}"}';
    const bytes = new TextEncoder().encode(text);
    assert.deepEqual(readJsonDocument(bytes, JSON_LIMITS.receipt), { a: '\u{e9}' });
    rejects(() => readJsonDocument(bytes, bytes.length - 1), 'json.too-large');
    rejects(
      () =>
        readJsonDocument(
          Uint8Array.from([...bytes.subarray(0, 7), 0xff, ...bytes.subarray(8)]),
          100,
        ),
      'json.syntax',
    );
    rejects(
      () => readJsonDocument(Uint8Array.from([0xef, 0xbb, 0xbf, ...bytes]), 100),
      'json.syntax',
    );
    // Text is measured in UTF-8 bytes, and a lone surrogate is the decoding of no UTF-8 at all.
    rejects(() => readJsonDocument(text, bytes.length - 1), 'json.too-large');
    assert.deepEqual(readJsonDocument(text, bytes.length), { a: '\u00e9' });
    assert.equal(utf8Length(text), bytes.length);
    rejects(() => readJsonDocument(`"${String.fromCharCode(0xd800)}"`, 100), 'json.syntax');
    rejects(() => readJsonDocument(42, 100), 'json.syntax');
    assert.ok(new StrictJsonError('json.syntax', 'x') instanceof Error);
  });
});

describe('the canonical form (spec section 3)', () => {
  test('reproduces the payload bytes of every vector whose payload.canonical passes, byte for byte', () => {
    let n = 0;
    for (const v of vectors) {
      if (v.expect.checks.find((c) => c.name === 'payload.canonical').outcome !== 'PASS') continue;
      const text = Buffer.from(
        (typeof v.input.receipt === 'string' ? JSON.parse(v.input.receipt) : v.input.receipt)
          .payload,
        'base64url',
      ).toString('utf8');
      assert.equal(canonicalize(JSON.parse(text)), text, v.id);
      n += 1;
    }
    assert.ok(n >= 60, `${n} payloads`);
  });

  test("RFC 8785 section 3.2.3's own sorting example: UTF-16 code-unit order, an astral key before U+FB33", () => {
    const input = JSON.parse(
      '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",' +
        '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
    );
    const expected =
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u{f6}":"Latin Small Letter O With Diaeresis",' +
      '"\u{20ac}":"Euro Sign","\u{1f600}":"Emoji: Grinning Face","\u{fb33}":"Hebrew Letter Dalet With Dagesh"}';
    assert.equal(canonicalize(input), expected);
  });

  test('refused values name their rule, and nothing that is not plain JSON is quietly converted', () => {
    const cases = [
      [null, 'canonical.null'],
      [true, 'canonical.boolean'],
      [1.5, 'canonical.float'],
      [Number.NaN, 'canonical.non-finite'],
      [Number.POSITIVE_INFINITY, 'canonical.non-finite'],
      [-0, 'canonical.negative-zero'],
      [2 ** 53, 'canonical.unsafe-integer'],
      [-(2 ** 53), 'canonical.unsafe-integer'],
      [String.fromCharCode(0x61, 0xd800, 0x62), 'canonical.lone-surrogate'],
      [String.fromCharCode(0xdc00), 'canonical.lone-surrogate'],
      ['\u{fdd0}', 'canonical.noncharacter'],
      ['\u{fdef}', 'canonical.noncharacter'],
      ['\u{fffe}', 'canonical.noncharacter'],
      ['\u{1ffff}', 'canonical.noncharacter'],
      ['\u{10ffff}', 'canonical.noncharacter'],
      [{ [String.fromCharCode(0xd800)]: 1 }, 'canonical.lone-surrogate'],
      [undefined, 'canonical.type'],
      [BigInt(10), 'canonical.type'],
      [{ issuedAt: new Date(0) }, 'canonical.type'],
      [{ salt: new Uint8Array(2) }, 'canonical.type'],
      [{ m: new Map([['a', 1]]) }, 'canonical.type'],
      [{ supersedes: undefined }, 'canonical.type'],
      [() => 1, 'canonical.type'],
    ];
    for (const [value, rule] of cases)
      assert.throws(
        () => canonicalize(value),
        (e) => e instanceof CanonicalError && e.rule === rule,
        rule,
      );
    assert.equal(canonicalize(Number.MAX_SAFE_INTEGER), '9007199254740991');
    assert.equal(canonicalize(-Number.MAX_SAFE_INTEGER), '-9007199254740991');
    assert.equal(canonicalize(Object.create(null)), '{}');
    assert.equal(canonicalize('\u{2028}\u007f\u0000\u001f'), '"\u{2028}\u007f\\u0000\\u001f"');
    assert.equal(
      canonicalize('\u{fdcf}\u{fdf0}\u{fffd}'),
      '"\u{fdcf}\u{fdf0}\u{fffd}"',
      'the neighbours of the noncharacters are admitted',
    );
    let deep = 1;
    for (let i = 0; i < 64; i += 1) deep = [deep];
    assert.equal(canonicalize(deep).length, 64 * 2 + 1);
    assert.throws(
      () => canonicalize([deep]),
      (e) => e.rule === 'canonical.depth',
    );
  });

  test('string serialization is exactly ECMA-262 QuoteJSONString for every BMP code point outside the surrogates', () => {
    for (let cp = 0; cp < 0x10000; cp += 1) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const s = String.fromCharCode(cp);
      assert.equal(quoteJsonString(`a${s}b`), JSON.stringify(`a${s}b`), cp.toString(16));
    }
    assert.equal(quoteJsonString('\u{1f600}'), '"\u{1f600}"');
  });

  test('member names are sorted by UTF-16 code unit, not by code point (vectors 30 and 31)', () => {
    assert.equal(canonicalize({ '\u{ff61}': 1, '\u{1f600}': 2 }), '{"\u{1f600}":2,"\u{ff61}":1}');
  });
});

describe('strict base64url, base64 and hex', () => {
  test('base64url: one spelling per byte string (spare bits zero, no padding, no stray character)', () => {
    for (let n = 0; n < 70; n += 1) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      const s = encodeBase64Url(bytes);
      assert.equal(s, Buffer.from(bytes).toString('base64url'));
      assert.deepEqual(decodeBase64Url(s), bytes);
    }
    assert.equal(decodeBase64Url('AB'), null, 'spare bits set');
    assert.deepEqual(decodeBase64Url('AA'), Uint8Array.of(0));
    assert.equal(decodeBase64Url('AAB'), null);
    assert.equal(decodeBase64Url('A'), null, 'a length of 4k+1 is no encoding');
    assert.equal(decodeBase64Url('AA=='), null, 'no padding in base64url');
    assert.equal(decodeBase64Url('A+A/'), null, 'the standard alphabet is not base64url');
    assert.equal(decodeBase64Url('AA\u{e9}A'), null);
    assert.equal(decodeBase64Url(12), null);
  });

  test('standard base64: padded, canonical', () => {
    for (let n = 0; n < 70; n += 1) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 91 + 7) & 0xff);
      const s = encodeBase64Std(bytes);
      assert.equal(s, Buffer.from(bytes).toString('base64'));
      assert.deepEqual(decodeBase64Std(s), bytes);
    }
    for (const bad of [
      'AA',
      'AB==',
      'AAB=',
      'A===',
      'AA=A',
      '=AAA',
      'AAAA=',
      'AA-_',
      'AAAAAB==',
      12,
    ])
      assert.equal(decodeBase64Std(bad), null, String(bad));
  });

  test('unverified values are described in ASCII, never dumped', () => {
    assert.deepEqual(
      [null, undefined, 'x"\\', 1.5, Number.NaN, true, [1, 2], {}, () => 1, Symbol('s')].map(
        describeValue,
      ),
      [
        'null',
        'nothing',
        '"x\\"\\\\"',
        '1.5',
        'a non-finite number',
        'true',
        'an array of 2',
        'an object',
        'a function',
        'a symbol',
      ],
    );
    assert.equal(quote('\u{1b}[2K'), '"\\u{1b}[2K"');
    assert.equal(quote('y'.repeat(65)), `"${'y'.repeat(64)}" (truncated)`);
    assert.equal(quoteFull('y'.repeat(65)), `"${'y'.repeat(65)}"`);
    assert.equal(asciiEscape(`a${String.fromCharCode(0xd800)}\u{1f600}`), 'a\\u{d800}\\u{1f600}');
  });

  test('hex is lowercase and even; UTF-16 well-formedness', () => {
    assert.equal(toHex(Uint8Array.of(0, 15, 255)), '000fff');
    assert.deepEqual(fromHex('000fff'), Uint8Array.of(0, 15, 255));
    for (const bad of ['0', 'AB', 'zz', 12]) assert.equal(fromHex(bad), null);
    assert.ok(isWellFormedUtf16('a\u{1f600}b'));
    assert.ok(!isWellFormedUtf16('a\ud83db'));
    assert.ok(!isWellFormedUtf16('\ude00'));
    assert.ok(!isWellFormedUtf16('\ud83d'));
  });
});
