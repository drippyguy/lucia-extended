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
var argon2id_exports = {};
__export(argon2id_exports, {
  Argon2id: () => Argon2id
});
module.exports = __toCommonJS(argon2id_exports);
var import_argon2 = require("@node-rs/argon2");
const v0x13 = 1;
class Argon2id {
  constructor(options) {
    this.memorySize = options?.memorySize ?? 19456;
    this.iterations = options?.iterations ?? 2;
    this.tagLength = options?.tagLength ?? 32;
    this.parallelism = options?.parallelism ?? 1;
    this.secret = options?.secret ?? null;
  }
  memorySize;
  iterations;
  tagLength;
  parallelism;
  secret;
  async hash(password) {
    return await (0, import_argon2.hash)(password.normalize("NFKC"), {
      memoryCost: this.memorySize,
      timeCost: this.iterations,
      outputLen: this.tagLength,
      parallelism: this.parallelism,
      version: v0x13,
      secret: this.secret ? Buffer.from(this.secret) : void 0
    });
  }
  async verify(hash2, password) {
    return await (0, import_argon2.verify)(hash2, password.normalize("NFKC"), {
      memoryCost: this.memorySize,
      timeCost: this.iterations,
      outputLen: this.tagLength,
      parallelism: this.parallelism,
      version: v0x13,
      secret: this.secret ? Buffer.from(this.secret) : void 0
    });
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Argon2id
});
//# sourceMappingURL=argon2id.cjs.map