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
var bytes_exports = {};
__export(bytes_exports, {
  binaryToInteger: () => binaryToInteger,
  byteToBinary: () => byteToBinary,
  bytesToBinary: () => bytesToBinary,
  bytesToInteger: () => bytesToInteger,
  compareBytes: () => compareBytes
});
module.exports = __toCommonJS(bytes_exports);
function byteToBinary(byte) {
  return byte.toString(2).padStart(8, "0");
}
function bytesToBinary(bytes) {
  return [...bytes].map((val) => byteToBinary(val)).join("");
}
function binaryToInteger(bits) {
  return parseInt(bits, 2);
}
function bytesToInteger(bytes) {
  return parseInt(bytesToBinary(bytes), 2);
}
function compareBytes(buffer1, buffer2) {
  const bytes1 = new Uint8Array(buffer1);
  const bytes2 = new Uint8Array(buffer2);
  if (bytes1.byteLength !== bytes2.byteLength)
    return false;
  for (let i = 0; i < bytes1.byteLength; i++) {
    if (bytes1[i] !== bytes2[i])
      return false;
  }
  return true;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  binaryToInteger,
  byteToBinary,
  bytesToBinary,
  bytesToInteger,
  compareBytes
});
//# sourceMappingURL=bytes.cjs.map