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
var sha_exports = {};
__export(sha_exports, {
  sha1: () => sha1,
  sha256: () => sha256,
  sha384: () => sha384,
  sha512: () => sha512
});
module.exports = __toCommonJS(sha_exports);
async function sha1(data) {
  return await crypto.subtle.digest("SHA-1", data);
}
async function sha256(data) {
  return await crypto.subtle.digest("SHA-256", data);
}
async function sha384(data) {
  return await crypto.subtle.digest("SHA-384", data);
}
async function sha512(data) {
  return await crypto.subtle.digest("SHA-512", data);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  sha1,
  sha256,
  sha384,
  sha512
});
//# sourceMappingURL=sha.cjs.map