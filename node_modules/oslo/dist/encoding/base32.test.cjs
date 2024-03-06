"use strict";
var import_vitest = require("vitest");
var import_base = require("@scure/base");
var import_base32 = require("./base32.cjs");
(0, import_vitest.describe)("Base32.encode()", () => {
  (0, import_vitest.test)("Generates valid string", () => {
    const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    for (const length of cases) {
      const data = crypto.getRandomValues(new Uint8Array(length));
      (0, import_vitest.expect)(import_base32.base32.encode(data)).toBe(import_base.base32.encode(data));
    }
  });
  (0, import_vitest.test)("Omits padding", () => {
    const data = crypto.getRandomValues(new Uint8Array(4));
    const result = import_base32.base32.encode(data, {
      includePadding: false
    });
    const expected = import_base32.base32.encode(data).replaceAll("=", "");
    (0, import_vitest.expect)(result).toBe(expected);
  });
});
(0, import_vitest.describe)("Base32.decode()", () => {
  (0, import_vitest.test)("Returns encoded data", () => {
    const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    for (const length of cases) {
      const data = crypto.getRandomValues(new Uint8Array(length));
      const encoded = import_base32.base32.encode(data);
      (0, import_vitest.expect)(import_base32.base32.decode(encoded)).toStrictEqual(data);
    }
  });
  (0, import_vitest.test)("Throws if data is missing padding in strict mode", () => {
    const data = crypto.getRandomValues(new Uint8Array(4));
    const encoded = import_base32.base32.encode(data, {
      includePadding: false
    });
    (0, import_vitest.expect)(() => import_base32.base32.decode(encoded.replaceAll("=", ""))).toThrow();
  });
  (0, import_vitest.test)("Accepts encoded data with missing padding if not in strict mode", () => {
    const data = crypto.getRandomValues(new Uint8Array(4));
    const encoded = import_base32.base32.encode(data, {
      includePadding: false
    });
    const result = import_base32.base32.decode(encoded.replaceAll("=", ""), {
      strict: false
    });
    (0, import_vitest.expect)(result).toStrictEqual(data);
  });
});
//# sourceMappingURL=base32.test.cjs.map