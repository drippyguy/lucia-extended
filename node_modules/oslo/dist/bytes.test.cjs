"use strict";
var import_vitest = require("vitest");
var import_bytes = require("./bytes.cjs");
(0, import_vitest.test)("bitsToInt()", () => {
  (0, import_vitest.expect)((0, import_bytes.binaryToInteger)("110100101000010101")).toBe(215573);
});
(0, import_vitest.test)("byteToBits()", () => {
  (0, import_vitest.expect)((0, import_bytes.byteToBinary)(101)).toBe("01100101");
});
(0, import_vitest.test)("bytesToBits()", () => {
  (0, import_vitest.expect)((0, import_bytes.bytesToBinary)(new Uint8Array([203, 3, 41, 76]))).toBe("11001011000000110010100101001100");
});
(0, import_vitest.test)("bytesToInteger()", () => {
  const bytes = Uint8Array.from([54, 204, 4, 128]);
  (0, import_vitest.expect)((0, import_bytes.bytesToInteger)(bytes)).toBe(new DataView(bytes.buffer).getUint32(0));
});
(0, import_vitest.test)("compareBytes()", () => {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  (0, import_vitest.expect)((0, import_bytes.compareBytes)(randomBytes, randomBytes)).toBe(true);
  const anotherRandomBytes = new Uint8Array(32);
  crypto.getRandomValues(anotherRandomBytes);
  (0, import_vitest.expect)((0, import_bytes.compareBytes)(randomBytes, anotherRandomBytes)).toBe(false);
});
//# sourceMappingURL=bytes.test.cjs.map