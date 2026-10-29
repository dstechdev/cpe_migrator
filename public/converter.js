/**
 * Conversor de serial de ONT (formato "traduzido" Parks/HubSoft -> HEX Huawei 16 chars).
 *
 * Regra:
 *  - 16 chars HEX  -> já está no formato Huawei, apenas upper-case.
 *  - 12 chars      -> 4 primeiros = Vendor ID (ASCII), 8 seguintes = sufixo HEX.
 *                     Cada char do Vendor vira seu código ASCII em HEX (2 dígitos).
 *                     Ex.: prks00d5e8e9 -> 50 52 4B 53 + 00D5E8E9 = 50524B5300D5E8E9
 *
 * Arquivo compartilhado: carregado no browser (window.SerialConverter) e no Node (require).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SerialConverter = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const HEX_16 = /^[0-9A-F]{16}$/;
  const VENDOR_4 = /^[A-Z0-9]{4}$/;
  const HEX_8 = /^[0-9A-F]{8}$/;

  /** Remove espaços, ":" e "-" que às vezes vêm copiados da OLT/planilha. */
  function normalize(raw) {
    return String(raw == null ? '' : raw).replace(/[\s:\-]/g, '').toUpperCase();
  }

  /**
   * @param {string} raw
   * @returns {{ ok: true, input: string, hex: string, vendor: string, vendorHex: string, suffix: string, alreadyHex: boolean }
   *         | { ok: false, input: string, error: string }}
   */
  function convert(raw) {
    const s = normalize(raw);
    const input = String(raw == null ? '' : raw).trim();

    if (!s) return { ok: false, input, error: 'Serial vazio.' };

    if (s.length === 16) {
      if (!HEX_16.test(s)) {
        return { ok: false, input, error: 'Serial de 16 caracteres deve conter apenas HEX (0-9, A-F).' };
      }
      const vendor = s
        .slice(0, 8)
        .match(/../g)
        .map((h) => String.fromCharCode(parseInt(h, 16)))
        .join('');
      return {
        ok: true,
        input,
        hex: s,
        vendor: /^[\x20-\x7E]{4}$/.test(vendor) ? vendor : '????',
        vendorHex: s.slice(0, 8),
        suffix: s.slice(8),
        alreadyHex: true,
      };
    }

    if (s.length === 12) {
      const vendor = s.slice(0, 4);
      const suffix = s.slice(4);
      if (!VENDOR_4.test(vendor)) {
        return { ok: false, input, error: `Vendor ID inválido "${vendor}" (esperado 4 caracteres alfanuméricos).` };
      }
      if (!HEX_8.test(suffix)) {
        return { ok: false, input, error: `Sufixo inválido "${suffix}" (esperado 8 caracteres HEX).` };
      }
      const vendorHex = Array.from(vendor)
        .map((c) => c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'))
        .join('');
      return { ok: true, input, hex: vendorHex + suffix, vendor, vendorHex, suffix, alreadyHex: false };
    }

    return {
      ok: false,
      input,
      error: `Tamanho inválido (${s.length}). Esperado 12 (ex: prks00d5e8e9) ou 16 (ex: 50524B5300D5E8E9).`,
    };
  }

  return { convert, normalize };
});
