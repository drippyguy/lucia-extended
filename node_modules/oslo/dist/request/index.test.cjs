"use strict";
var import_index = require("./index.cjs");
var import_vitest = require("vitest");
(0, import_vitest.describe)("verifyRequestOrigin()", () => {
  (0, import_vitest.test)("checks if origin and host matches", () => {
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.com", ["example.com"])).toBe(true);
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.co.jp", ["example.co.jp"])).toBe(true);
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.com", ["invalid.com"])).toBe(false);
  });
  (0, import_vitest.test)("allows full urls for host", () => {
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.com", ["https://example.com"])).toBe(true);
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.co.jp", ["https://example.co.jp"])).toBe(true);
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.com", ["https://invalid.com"])).toBe(false);
  });
  (0, import_vitest.test)("checks port", () => {
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.com:1000", ["example.com:1000"])).toBe(true);
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("https://example.com:1000", ["example.com:2000"])).toBe(false);
  });
  (0, import_vitest.test)("IDN", () => {
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("http://xn--zckzah.com", ["xn--zckzah.com"])).toBe(true);
    (0, import_vitest.expect)((0, import_index.verifyRequestOrigin)("http://xn--zckzah.com", ["\u30C6\u30B9\u30C8.com"])).toBe(true);
  });
});
//# sourceMappingURL=index.test.cjs.map