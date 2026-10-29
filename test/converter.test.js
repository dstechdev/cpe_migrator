'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { convert } = require('../public/converter');

test('prks (12 chars) -> HEX', () => {
  assert.strictEqual(convert('prks00d5e8e9').hex, '50524B5300D5E8E9');
});

test('hwtc (12 chars) -> HEX', () => {
  assert.strictEqual(convert('hwtc9db6abb4').hex, '485754439DB6ABB4');
});

test('16 chars já em HEX apenas normaliza', () => {
  const r = convert('50524b5300d5e8e9');
  assert.strictEqual(r.hex, '50524B5300D5E8E9');
  assert.strictEqual(r.alreadyHex, true);
  assert.strictEqual(r.vendor, 'PRKS');
});

test('aceita separadores e espaços', () => {
  assert.strictEqual(convert('  PRKS-00D5E8E9 ').hex, '50524B5300D5E8E9');
});

test('rejeita sufixo não-HEX', () => {
  assert.strictEqual(convert('prks00d5e8eZ').ok, false);
});

test('rejeita tamanho inválido', () => {
  assert.strictEqual(convert('prks00d5').ok, false);
  assert.strictEqual(convert('').ok, false);
});
