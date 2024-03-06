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
var random_exports = {};
__export(random_exports, {
  alphabet: () => alphabet,
  generateRandomInteger: () => generateRandomInteger,
  generateRandomString: () => generateRandomString,
  random: () => random
});
module.exports = __toCommonJS(random_exports);
var import_bytes = require("../bytes.cjs");
function random() {
  const buffer = new ArrayBuffer(8);
  const bytes = crypto.getRandomValues(new Uint8Array(buffer));
  bytes[0] = 63;
  bytes[1] = bytes[1] | 240;
  return new DataView(buffer).getFloat64(0) - 1;
}
function generateRandomInteger(max) {
  if (max < 0 || !Number.isInteger(max)) {
    throw new Error("Argument 'max' must be an integer greater than or equal to 0");
  }
  const bitLength = (max - 1).toString(2).length;
  const shift = bitLength % 8;
  const bytes = new Uint8Array(Math.ceil(bitLength / 8));
  crypto.getRandomValues(bytes);
  if (shift !== 0) {
    bytes[0] &= (1 << shift) - 1;
  }
  let result = (0, import_bytes.bytesToInteger)(bytes);
  while (result >= max) {
    crypto.getRandomValues(bytes);
    if (shift !== 0) {
      bytes[0] &= (1 << shift) - 1;
    }
    result = (0, import_bytes.bytesToInteger)(bytes);
  }
  return result;
}
function generateRandomString(length, alphabet2) {
  let result = "";
  for (let i = 0; i < length; i++) {
    result += alphabet2[generateRandomInteger(alphabet2.length)];
  }
  return result;
}
function alphabet(...patterns) {
  const patternSet = new Set(patterns);
  let result = "";
  for (const pattern of patternSet) {
    if (pattern === "a-z") {
      result += "abcdefghijklmnopqrstuvwxyz";
    } else if (pattern === "A-Z") {
      result += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    } else if (pattern === "0-9") {
      result += "0123456789";
    } else {
      result += pattern;
    }
  }
  return result;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  alphabet,
  generateRandomInteger,
  generateRandomString,
  random
});
//# sourceMappingURL=random.cjs.map