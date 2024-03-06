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
var request_exports = {};
__export(request_exports, {
  verifyRequestOrigin: () => verifyRequestOrigin
});
module.exports = __toCommonJS(request_exports);
function verifyRequestOrigin(origin, allowedDomains) {
  if (!origin || allowedDomains.length === 0)
    return false;
  const originHost = safeURL(origin)?.host ?? null;
  if (!originHost)
    return false;
  for (const domain of allowedDomains) {
    let host;
    if (domain.startsWith("http://") || domain.startsWith("https://")) {
      host = safeURL(domain)?.host ?? null;
    } else {
      host = safeURL("https://" + domain)?.host ?? null;
    }
    if (originHost === host)
      return true;
  }
  return false;
}
function safeURL(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  verifyRequestOrigin
});
//# sourceMappingURL=index.cjs.map