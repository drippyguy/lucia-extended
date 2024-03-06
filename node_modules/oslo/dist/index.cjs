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
  TimeSpan: () => TimeSpan,
  createDate: () => createDate,
  isWithinExpirationDate: () => isWithinExpirationDate
});
module.exports = __toCommonJS(src_exports);
class TimeSpan {
  constructor(value, unit) {
    this.value = value;
    this.unit = unit;
  }
  value;
  unit;
  milliseconds() {
    if (this.unit === "ms") {
      return this.value;
    }
    if (this.unit === "s") {
      return this.value * 1e3;
    }
    if (this.unit === "m") {
      return this.value * 1e3 * 60;
    }
    if (this.unit === "h") {
      return this.value * 1e3 * 60 * 60;
    }
    if (this.unit === "d") {
      return this.value * 1e3 * 60 * 60 * 24;
    }
    return this.value * 1e3 * 60 * 60 * 24 * 7;
  }
  seconds() {
    return this.milliseconds() / 1e3;
  }
  transform(x) {
    return new TimeSpan(Math.round(this.milliseconds() * x), "ms");
  }
}
function isWithinExpirationDate(date) {
  return Date.now() < date.getTime();
}
function createDate(timeSpan) {
  return new Date(Date.now() + timeSpan.milliseconds());
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TimeSpan,
  createDate,
  isWithinExpirationDate
});
//# sourceMappingURL=index.cjs.map