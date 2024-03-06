"use strict";
var import_vitest = require("vitest");
var import_hex = require("./hex.cjs");
(0, import_vitest.describe)("encodeHex()", () => {
  (0, import_vitest.test)("Generates valid hex string", () => {
    const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    for (const length of cases) {
      const data = crypto.getRandomValues(new Uint8Array(length));
      (0, import_vitest.expect)((0, import_hex.encodeHex)(data)).toBe(Buffer.from(data).toString("hex"));
    }
  });
});
(0, import_vitest.describe)("Base32.decode()", () => {
  (0, import_vitest.test)("Returns encoded data", () => {
    const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    for (const length of cases) {
      const data = crypto.getRandomValues(new Uint8Array(length));
      const encoded = (0, import_hex.encodeHex)(data);
      (0, import_vitest.expect)((0, import_hex.decodeHex)(encoded)).toStrictEqual(data);
      (0, import_vitest.expect)((0, import_hex.decodeHex)(encoded.toUpperCase())).toStrictEqual(data);
    }
  });
  (0, import_vitest.test)("Throws if data is invalid", () => {
    (0, import_vitest.expect)(() => (0, import_hex.decodeHex)("a")).toThrow();
  });
});
//# sourceMappingURL=hex.test.cjs.map