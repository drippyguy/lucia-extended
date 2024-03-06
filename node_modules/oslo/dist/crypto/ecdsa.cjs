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
var ecdsa_exports = {};
__export(ecdsa_exports, {
  ECDSA: () => ECDSA
});
module.exports = __toCommonJS(ecdsa_exports);
class ECDSA {
  hash;
  curve;
  constructor(hash, curve) {
    this.hash = hash;
    this.curve = curve;
  }
  async sign(privateKey, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      privateKey,
      {
        name: "ECDSA",
        namedCurve: this.curve
      },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: this.hash
      },
      cryptoKey,
      data
    );
    return signature;
  }
  async verify(publicKey, signature, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "spki",
      publicKey,
      {
        name: "ECDSA",
        namedCurve: this.curve
      },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: this.hash
      },
      cryptoKey,
      signature,
      data
    );
  }
  async generateKeyPair() {
    const cryptoKeyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: this.curve
      },
      true,
      ["sign"]
    );
    const privateKey = await crypto.subtle.exportKey("pkcs8", cryptoKeyPair.privateKey);
    const publicKey = await crypto.subtle.exportKey("spki", cryptoKeyPair.publicKey);
    return {
      privateKey,
      publicKey
    };
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  ECDSA
});
//# sourceMappingURL=ecdsa.cjs.map