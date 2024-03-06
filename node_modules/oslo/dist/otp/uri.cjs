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
var uri_exports = {};
__export(uri_exports, {
  createHOTPKeyURI: () => createHOTPKeyURI,
  createTOTPKeyURI: () => createTOTPKeyURI
});
module.exports = __toCommonJS(uri_exports);
var import_encoding = require("../encoding/index.cjs");
function createTOTPKeyURI(issuer, accountName, secret, options) {
  const [baseURI, params] = createKeyURIBase("totp", issuer, accountName, secret, options);
  if (options?.period !== void 0) {
    params.set("period", options.period.seconds().toString());
  }
  return baseURI + "?" + params.toString();
}
function createHOTPKeyURI(issuer, accountName, secret, options) {
  const [baseURI, params] = createKeyURIBase("hotp", issuer, accountName, secret, options);
  const counter = options?.counter ?? 0;
  params.set("counter", counter.toString());
  return baseURI + "?" + params.toString();
}
function createKeyURIBase(type, issuer, accountName, secret, options) {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccountName = encodeURIComponent(accountName);
  const baseURI = `otpauth://${type}/${encodedIssuer}:${encodedAccountName}`;
  const params = new URLSearchParams({
    secret: import_encoding.base32.encode(new Uint8Array(secret), {
      includePadding: false
    }),
    issuer: encodedIssuer
  });
  if (options?.digits !== void 0) {
    params.set("digits", options.digits.toString());
  }
  return [baseURI, params];
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createHOTPKeyURI,
  createTOTPKeyURI
});
//# sourceMappingURL=uri.cjs.map