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
var totp_exports = {};
__export(totp_exports, {
  TOTPController: () => TOTPController
});
module.exports = __toCommonJS(totp_exports);
var import__ = require("../index.cjs");
var import_hotp = require("./hotp.cjs");
class TOTPController {
  digits;
  period;
  constructor(options) {
    this.digits = options?.digits ?? 6;
    this.period = options?.period ?? new import__.TimeSpan(30, "s");
  }
  async generate(secret) {
    const counter = Math.floor(Date.now() / this.period.milliseconds());
    return await (0, import_hotp.generateHOTP)(secret, counter, this.digits);
  }
  async verify(totp, secret) {
    const expectedTOTP = await this.generate(secret);
    return totp === expectedTOTP;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TOTPController
});
//# sourceMappingURL=totp.cjs.map