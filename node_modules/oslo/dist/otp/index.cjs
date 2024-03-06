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
var otp_exports = {};
__export(otp_exports, {
  TOTPController: () => import_totp.TOTPController,
  createHOTPKeyURI: () => import_uri.createHOTPKeyURI,
  createTOTPKeyURI: () => import_uri.createTOTPKeyURI,
  generateHOTP: () => import_hotp.generateHOTP
});
module.exports = __toCommonJS(otp_exports);
var import_hotp = require("./hotp.cjs");
var import_totp = require("./totp.cjs");
var import_uri = require("./uri.cjs");
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TOTPController,
  createHOTPKeyURI,
  createTOTPKeyURI,
  generateHOTP
});
//# sourceMappingURL=index.cjs.map