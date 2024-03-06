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
var scrypt_exports = {};
__export(scrypt_exports, {
  Scrypt: () => Scrypt
});
module.exports = __toCommonJS(scrypt_exports);
var import_node_crypto = require("node:crypto");
var import_encoding = require("../encoding/index.cjs");
var import_crypto = require("../crypto/index.cjs");
class Scrypt {
  constructor(options) {
    this.N = options?.N ?? 16384;
    this.r = options?.r ?? 16;
    this.p = options?.p ?? 1;
    this.dkLen = options?.dkLen ?? 64;
  }
  N;
  r;
  p;
  dkLen;
  async hash(password) {
    const salt = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(16)));
    const key = await this.generateKey(password, salt);
    return `${salt}:${(0, import_encoding.encodeHex)(key)}`;
  }
  async verify(hash, password) {
    const [salt, key] = hash.split(":");
    const targetKey = await this.generateKey(password, salt);
    return (0, import_crypto.constantTimeEqual)(targetKey, (0, import_encoding.decodeHex)(key));
  }
  async generateKey(password, salt) {
    return await new Promise((resolve, reject) => {
      (0, import_node_crypto.scrypt)(
        password.normalize("NFKC"),
        salt,
        this.dkLen,
        {
          N: this.N,
          p: this.p,
          r: this.r,
          // errors when 128 * N * r > `maxmem` (approximately)
          maxmem: 128 * this.N * this.r * 2
        },
        (err, buff) => {
          if (err)
            return reject(err);
          return resolve(buff);
        }
      );
    });
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Scrypt
});
//# sourceMappingURL=scrypt.cjs.map