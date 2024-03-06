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
var hmac_exports = {};
__export(hmac_exports, {
  HMAC: () => HMAC
});
module.exports = __toCommonJS(hmac_exports);
class HMAC {
  hash;
  constructor(hash) {
    this.hash = hash;
  }
  async verify(key, signature, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      {
        name: "HMAC",
        hash: this.hash
      },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify("HMAC", cryptoKey, signature, data);
  }
  async sign(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      {
        name: "HMAC",
        hash: this.hash
      },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, data);
    return signature;
  }
  async generateKey() {
    const cryptoKey = await crypto.subtle.generateKey(
      {
        name: "HMAC",
        hash: this.hash
      },
      true,
      ["sign"]
    );
    const key = await crypto.subtle.exportKey("raw", cryptoKey);
    return key;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  HMAC
});
//# sourceMappingURL=hmac.cjs.map