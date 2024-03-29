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
var src_exports = {};
__export(src_exports, {
  Cookie: () => import_cookie.Cookie,
  LegacyScrypt: () => import_crypto.LegacyScrypt,
  Lucia: () => import_core.Lucia,
  Scrypt: () => import_crypto.Scrypt,
  TimeSpan: () => import_oslo.TimeSpan,
  generateId: () => import_crypto.generateId,
  verifyRequestOrigin: () => import_request.verifyRequestOrigin
});
module.exports = __toCommonJS(src_exports);
var import_core = require("./core.cjs");
var import_crypto = require("./crypto.cjs");
var import_oslo = require("oslo");
var import_cookie = require("oslo/cookie");
var import_request = require("oslo/request");
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Cookie,
  LegacyScrypt,
  Lucia,
  Scrypt,
  TimeSpan,
  generateId,
  verifyRequestOrigin
});
//# sourceMappingURL=index.cjs.map