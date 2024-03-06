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
var crypto_exports = {};
__export(crypto_exports, {
  LegacyScrypt: () => LegacyScrypt,
  Scrypt: () => Scrypt,
  generateId: () => generateId
});
module.exports = __toCommonJS(crypto_exports);
var import_encoding = require("oslo/encoding");
var import_crypto = require("oslo/crypto");
var import_scrypt = require("./scrypt/index.cjs");
async function generateScryptKey(data, salt, blockSize = 16) {
  const encodedData = new TextEncoder().encode(data);
  const encodedSalt = new TextEncoder().encode(salt);
  const keyUint8Array = await (0, import_scrypt.scrypt)(encodedData, encodedSalt, {
    N: 16384,
    r: blockSize,
    p: 1,
    dkLen: 64
  });
  return keyUint8Array;
}
function generateId(length) {
  return (0, import_crypto.generateRandomString)(length, (0, import_crypto.alphabet)("0-9", "a-z"));
}
class Scrypt {
  async hash(password) {
    const salt = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(16)));
    const key = await generateScryptKey(password.normalize("NFKC"), salt);
    return `${salt}:${(0, import_encoding.encodeHex)(key)}`;
  }
  async verify(hash, password) {
    const parts = hash.split(":");
    if (parts.length !== 2)
      return false;
    const [salt, key] = parts;
    const targetKey = await generateScryptKey(password.normalize("NFKC"), salt);
    return (0, import_crypto.constantTimeEqual)(targetKey, (0, import_encoding.decodeHex)(key));
  }
}
class LegacyScrypt {
  async hash(password) {
    const salt = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(16)));
    const key = await generateScryptKey(password.normalize("NFKC"), salt);
    return `s2:${salt}:${(0, import_encoding.encodeHex)(key)}`;
  }
  async verify(hash, password) {
    const parts = hash.split(":");
    if (parts.length === 2) {
      const [salt2, key2] = parts;
      const targetKey = await generateScryptKey(password.normalize("NFKC"), salt2, 8);
      const result = (0, import_crypto.constantTimeEqual)(targetKey, (0, import_encoding.decodeHex)(key2));
      return result;
    }
    if (parts.length !== 3)
      return false;
    const [version, salt, key] = parts;
    if (version === "s2") {
      const targetKey = await generateScryptKey(password.normalize("NFKC"), salt);
      return (0, import_crypto.constantTimeEqual)(targetKey, (0, import_encoding.decodeHex)(key));
    }
    return false;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  LegacyScrypt,
  Scrypt,
  generateId
});
//# sourceMappingURL=crypto.cjs.map