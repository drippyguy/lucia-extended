"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var base32_exports = {};
__export(base32_exports, {
  Base32Encoding: () => Base32Encoding,
  base32: () => base32,
  base32hex: () => base32hex,
  decodeBase32: () => decodeBase32,
  encodeBase32: () => encodeBase32
});
module.exports = __toCommonJS(base32_exports);
class Base32Encoding {
  alphabet;
  padding;
  decodeMap = /* @__PURE__ */ new Map();
  constructor(alphabet, options) {
    if (alphabet.length !== 32) {
      throw new Error("Invalid alphabet");
    }
    this.alphabet = alphabet;
    this.padding = options?.padding ?? "=";
    if (this.alphabet.includes(this.padding) || this.padding.length !== 1) {
      throw new Error("Invalid padding");
    }
    for (let i = 0; i < alphabet.length; i++) {
      this.decodeMap.set(alphabet[i], i);
    }
  }
  encode(data, options) {
    let result = "";
    let buffer = 0;
    let shift = 0;
    for (let i = 0; i < data.length; i++) {
      buffer = buffer << 8 | data[i];
      shift += 8;
      while (shift >= 5) {
        shift -= 5;
        result += this.alphabet[buffer >> shift & 31];
      }
    }
    if (shift > 0) {
      result += this.alphabet[buffer << 5 - shift & 31];
    }
    const includePadding = options?.includePadding ?? true;
    if (includePadding) {
      const padCount = (8 - result.length % 8) % 8;
      for (let i = 0; i < padCount; i++) {
        result += "=";
      }
    }
    return result;
  }
  decode(data, options) {
    const strict = options?.strict ?? true;
    const chunkCount = Math.ceil(data.length / 8);
    const result = [];
    for (let i = 0; i < chunkCount; i++) {
      let padCount = 0;
      const chunks = [];
      for (let j = 0; j < 8; j++) {
        const encoded = data[i * 8 + j];
        if (encoded === "=") {
          if (i + 1 !== chunkCount) {
            throw new Error(`Invalid character: ${encoded}`);
          }
          padCount += 1;
          continue;
        }
        if (encoded === void 0) {
          if (strict) {
            throw new Error("Invalid data");
          }
          padCount += 1;
          continue;
        }
        const value = this.decodeMap.get(encoded) ?? null;
        if (value === null) {
          throw new Error(`Invalid character: ${encoded}`);
        }
        chunks.push(value);
      }
      if (padCount === 8 || padCount === 7 || padCount === 5 || padCount === 2) {
        throw new Error("Invalid padding");
      }
      const byte1 = (chunks[0] << 3) + (chunks[1] >> 2);
      result.push(byte1);
      if (padCount < 6) {
        const byte2 = ((chunks[1] & 3) << 6) + (chunks[2] << 1) + (chunks[3] >> 4);
        result.push(byte2);
      }
      if (padCount < 4) {
        const byte3 = ((chunks[3] & 255) << 4) + (chunks[4] >> 1);
        result.push(byte3);
      }
      if (padCount < 3) {
        const byte4 = ((chunks[4] & 1) << 7) + (chunks[5] << 2) + (chunks[6] >> 3);
        result.push(byte4);
      }
      if (padCount < 1) {
        const byte5 = ((chunks[6] & 7) << 5) + chunks[7];
        result.push(byte5);
      }
    }
    return Uint8Array.from(result);
  }
}
const base32 = new Base32Encoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
const base32hex = new Base32Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUV");
function encodeBase32(data, options) {
  return base32.encode(new Uint8Array(data), {
    includePadding: options?.padding ?? true
  });
}
function decodeBase32(data) {
  return base32.decode(data, {
    strict: false
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Base32Encoding,
  base32,
  base32hex,
  decodeBase32,
  encodeBase32
});
//# sourceMappingURL=base32.cjs.map