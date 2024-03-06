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
var bcrypt_exports = {};
__export(bcrypt_exports, {
  Bcrypt: () => Bcrypt
});
module.exports = __toCommonJS(bcrypt_exports);
var import_bcrypt = require("@node-rs/bcrypt");
class Bcrypt {
  constructor(options) {
    this.cost = options?.cost ?? 10;
  }
  cost;
  async hash(password) {
    return await (0, import_bcrypt.hash)(password.normalize("NFKC"), this.cost);
  }
  async verify(hash2, password) {
    return await (0, import_bcrypt.verify)(password.normalize("NFKC"), hash2);
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Bcrypt
});
//# sourceMappingURL=bcrypt.cjs.map