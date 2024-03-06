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
var base64_exports = {};
__export(base64_exports, {
  Base64Encoding: () => Base64Encoding,
  base64: () => base64,
  base64url: () => base64url,
  decodeBase64: () => decodeBase64,
  decodeBase64url: () => decodeBase64url,
  encodeBase64: () => encodeBase64,
  encodeBase64url: () => encodeBase64url
});
module.exports = __toCommonJS(base64_exports);
class Base64Encoding {
  alphabet;
  padding;
  decodeMap = /* @__PURE__ */ new Map();
  constructor(alphabet, options) {
    if (alphabet.length !== 64) {
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
      while (shift >= 6) {
        shift += -6;
        result += this.alphabet[buffer >> shift & 63];
      }
    }
    if (shift > 0) {
      result += this.alphabet[buffer << 6 - shift & 63];
    }
    const includePadding = options?.includePadding ?? true;
    if (includePadding) {
      const padCount = (4 - result.length % 4) % 4;
      for (let i = 0; i < padCount; i++) {
        result += "=";
      }
    }
    return result;
  }
  decode(data, options) {
    const strict = options?.strict ?? true;
    const chunkCount = Math.ceil(data.length / 4);
    const result = [];
    for (let i = 0; i < chunkCount; i++) {
      let padCount = 0;
      let buffer = 0;
      for (let j = 0; j < 4; j++) {
        const encoded = data[i * 4 + j];
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
        buffer += value << 6 * (3 - j);
      }
      result.push(buffer >> 16 & 255);
      if (padCount < 2) {
        result.push(buffer >> 8 & 255);
      }
      if (padCount < 1) {
        result.push(buffer & 255);
      }
    }
    return Uint8Array.from(result);
  }
}
const base64 = new Base64Encoding(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
);
const base64url = new Base64Encoding(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
);
function encodeBase64(data, options) {
  return base64.encode(new Uint8Array(data), {
    includePadding: options?.padding ?? true
  });
}
function decodeBase64(data) {
  return base64.decode(data, {
    strict: false
  });
}
function encodeBase64url(data) {
  return base64.encode(new Uint8Array(data), {
    includePadding: false
  });
}
function decodeBase64url(data) {
  return base64url.decode(data, {
    strict: false
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Base64Encoding,
  base64,
  base64url,
  decodeBase64,
  decodeBase64url,
  encodeBase64,
  encodeBase64url
});
//# sourceMappingURL=base64.cjs.map