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
var encoding_exports = {};
__export(encoding_exports, {
  Base32Encoding: () => import_base32.Base32Encoding,
  Base64Encoding: () => import_base64.Base64Encoding,
  base32: () => import_base32.base32,
  base32hex: () => import_base32.base32hex,
  base64: () => import_base64.base64,
  base64url: () => import_base64.base64url,
  decodeBase32: () => import_base322.decodeBase32,
  decodeBase64: () => import_base642.decodeBase64,
  decodeBase64url: () => import_base642.decodeBase64url,
  decodeHex: () => import_hex.decodeHex,
  encodeBase32: () => import_base322.encodeBase32,
  encodeBase64: () => import_base642.encodeBase64,
  encodeBase64url: () => import_base642.encodeBase64url,
  encodeHex: () => import_hex.encodeHex
});
module.exports = __toCommonJS(encoding_exports);
var import_hex = require("./hex.cjs");
var import_base32 = require("./base32.cjs");
var import_base64 = require("./base64.cjs");
var import_base322 = require("./base32.cjs");
var import_base642 = require("./base64.cjs");
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Base32Encoding,
  Base64Encoding,
  base32,
  base32hex,
  base64,
  base64url,
  decodeBase32,
  decodeBase64,
  decodeBase64url,
  decodeHex,
  encodeBase32,
  encodeBase64,
  encodeBase64url,
  encodeHex
});
//# sourceMappingURL=index.cjs.map