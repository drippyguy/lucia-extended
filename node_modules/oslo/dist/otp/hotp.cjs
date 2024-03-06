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
var hotp_exports = {};
__export(hotp_exports, {
  generateHOTP: () => generateHOTP
});
module.exports = __toCommonJS(hotp_exports);
var import_bytes = require("../bytes.cjs");
var import_hmac = require("../crypto/hmac.cjs");
async function generateHOTP(key, counter, digits = 6) {
  if (digits > 8) {
    throw new TypeError("Digits must be 8 or smaller");
  }
  const counterBytes = intTo8Bytes(counter);
  const HS = await new import_hmac.HMAC("SHA-1").sign(key, counterBytes);
  const SBites = truncate(new Uint8Array(HS));
  const SNum = (0, import_bytes.binaryToInteger)(SBites);
  const D = SNum % 10 ** digits;
  return D.toString().padStart(digits, "0");
}
function truncate(data) {
  const offset = (0, import_bytes.binaryToInteger)((0, import_bytes.byteToBinary)(data[data.byteLength - 1]).slice(4));
  return (0, import_bytes.bytesToBinary)(data).slice(offset * 8 + 1, (offset + 4) * 8);
}
function intTo8Bytes(int) {
  const result = new Uint8Array(8);
  const bits = int.toString(2).padStart(8 * 8, "0");
  for (let i = 0; i < 8; i++) {
    result[i] = (0, import_bytes.binaryToInteger)(bits.slice(i * 8, (i + 1) * 8));
  }
  return result;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  generateHOTP
});
//# sourceMappingURL=hotp.cjs.map