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
var rsa_exports = {};
__export(rsa_exports, {
  RSASSAPKCS1v1_5: () => RSASSAPKCS1v1_5,
  RSASSAPSS: () => RSASSAPSS
});
module.exports = __toCommonJS(rsa_exports);
class RSASSAPKCS1v1_5 {
  hash;
  constructor(hash) {
    this.hash = hash;
  }
  async verify(publicKey, signature, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "spki",
      publicKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: this.hash
      },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, data);
  }
  async sign(privateKey, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      privateKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: this.hash
      },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, data);
    return signature;
  }
  async generateKeyPair(modulusLength) {
    const cryptoKeyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: this.hash,
        modulusLength: modulusLength ?? 2048,
        publicExponent: new Uint8Array([1, 0, 1])
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
class RSASSAPSS {
  hash;
  saltLength;
  constructor(hash) {
    this.hash = hash;
    if (hash === "SHA-1") {
      this.saltLength = 20;
    } else if (hash === "SHA-256") {
      this.saltLength = 32;
    } else if (hash === "SHA-384") {
      this.saltLength = 48;
    } else {
      this.saltLength = 64;
    }
  }
  async verify(publicKey, signature, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "spki",
      publicKey,
      {
        name: "RSA-PSS",
        hash: this.hash
      },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: this.saltLength
      },
      cryptoKey,
      signature,
      data
    );
  }
  async sign(privateKey, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      privateKey,
      {
        name: "RSA-PSS",
        hash: this.hash
      },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: this.saltLength
      },
      cryptoKey,
      data
    );
    return signature;
  }
  async generateKeyPair(modulusLength) {
    const cryptoKeyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        hash: this.hash,
        modulusLength: modulusLength ?? 2048,
        publicExponent: new Uint8Array([1, 0, 1])
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
  RSASSAPKCS1v1_5,
  RSASSAPSS
});
//# sourceMappingURL=rsa.cjs.map