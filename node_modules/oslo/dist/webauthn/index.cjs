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
var webauthn_exports = {};
__export(webauthn_exports, {
  WebAuthnController: () => WebAuthnController
});
module.exports = __toCommonJS(webauthn_exports);
var import_encoding = require("../encoding/index.cjs");
var import_bytes = require("../bytes.cjs");
var import_crypto = require("../crypto/index.cjs");
class WebAuthnController {
  originURL;
  constructor(origin) {
    this.originURL = new URL(origin);
  }
  async validateAttestationResponse(response, challenge) {
    const validClientDataJSON = this.verifyClientDataJSON(
      "webauthn.create",
      response.clientDataJSON,
      challenge
    );
    if (!validClientDataJSON) {
      throw new Error("Failed to validate client data JSON");
    }
    const validAuthenticatorData = await this.verifyAuthenticatorData(response.authenticatorData);
    if (!validAuthenticatorData) {
      throw new Error("Failed to validate authenticator data");
    }
  }
  async validateAssertionResponse(algorithm, publicKey, response, challenge) {
    const validClientDataJSON = this.verifyClientDataJSON(
      "webauthn.get",
      response.clientDataJSON,
      challenge
    );
    if (!validClientDataJSON) {
      throw new Error("Failed to validate client data JSON");
    }
    const validAuthenticatorData = await this.verifyAuthenticatorData(response.authenticatorData);
    if (!validAuthenticatorData) {
      throw new Error("Failed to validate authenticator data");
    }
    if (algorithm === "ES256") {
      const signature = convertDERSignatureToECDSASignature(response.signature);
      const hash = await crypto.subtle.digest("SHA-256", response.clientDataJSON);
      const data = concatenateBuffer(response.authenticatorData, hash);
      const es256 = new import_crypto.ECDSA("SHA-256", "P-256");
      const validSignature = await es256.verify(publicKey, signature, data);
      if (!validSignature) {
        throw new Error("Failed to validate signature");
      }
    } else if (algorithm === "RS256") {
      const signature = convertDERSignatureToECDSASignature(response.signature);
      const hash = await crypto.subtle.digest("SHA-256", response.clientDataJSON);
      const data = concatenateBuffer(response.authenticatorData, hash);
      const rs256 = new import_crypto.RSASSAPKCS1v1_5("SHA-256");
      const validSignature = await rs256.verify(publicKey, signature, data);
      if (!validSignature) {
        throw new Error("Failed to validate signature");
      }
    } else {
      throw new TypeError(`Unknown algorithm: ${algorithm}`);
    }
  }
  verifyClientDataJSON(type, clientDataJSON, challenge) {
    const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
    if (!clientData || typeof clientData !== "object") {
      return false;
    }
    if (!("type" in clientData) || clientData.type !== type) {
      return false;
    }
    if (!("challenge" in clientData) || typeof clientData.challenge !== "string") {
      return false;
    }
    const clientDataChallengeBuffer = import_encoding.base64url.decode(clientData.challenge, {
      strict: false
    });
    if (!(0, import_bytes.compareBytes)(clientDataChallengeBuffer, challenge)) {
      return false;
    }
    if (!("origin" in clientData) || clientData.origin !== this.originURL.origin) {
      return false;
    }
    return true;
  }
  async verifyAuthenticatorData(authenticatorData) {
    const authData = new Uint8Array(authenticatorData);
    if (authData.byteLength < 37) {
      return false;
    }
    const rpIdHash = authData.slice(0, 32);
    const rpIdData = new TextEncoder().encode(this.originURL.hostname);
    const expectedRpIdHash = await crypto.subtle.digest("SHA-256", rpIdData);
    if (!(0, import_bytes.compareBytes)(rpIdHash, expectedRpIdHash)) {
      return false;
    }
    const flagsBits = authData[32].toString(2);
    if (flagsBits.charAt(flagsBits.length - 1) !== "1") {
      return false;
    }
    return true;
  }
}
function convertDERSignatureToECDSASignature(DERSignature) {
  const signatureBytes = new Uint8Array(DERSignature);
  const rStart = 4;
  const rLength = signatureBytes[3];
  const rEnd = rStart + rLength;
  const DEREncodedR = signatureBytes.slice(rStart, rEnd);
  const r = decodeDERInteger(DEREncodedR, 32);
  const sStart = rEnd + 2;
  const sEnd = signatureBytes.byteLength;
  const DEREncodedS = signatureBytes.slice(sStart, sEnd);
  const s = decodeDERInteger(DEREncodedS, 32);
  const ECDSASignature = new Uint8Array([...r, ...s]);
  return ECDSASignature.buffer;
}
function decodeDERInteger(integerBytes, expectedLength) {
  if (integerBytes.byteLength === expectedLength)
    return integerBytes;
  if (integerBytes.byteLength < expectedLength) {
    return concatenateUint8Array(
      // add leading 0x00s if smaller than expected length
      new Uint8Array(expectedLength - integerBytes.byteLength).fill(0),
      integerBytes
    );
  }
  return integerBytes.slice(-32);
}
function concatenateBuffer(buffer1, buffer2) {
  return concatenateUint8Array(new Uint8Array(buffer1), new Uint8Array(buffer2)).buffer;
}
function concatenateUint8Array(bytes1, bytes2) {
  const result = new Uint8Array(bytes1.byteLength + bytes2.byteLength);
  result.set(new Uint8Array(bytes1), 0);
  result.set(new Uint8Array(bytes2), bytes1.byteLength);
  return result;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  WebAuthnController
});
//# sourceMappingURL=index.cjs.map