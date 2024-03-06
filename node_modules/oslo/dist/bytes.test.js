"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const bytes_js_1 = require("./bytes.js");
(0, vitest_1.test)("bitsToInt()", () => {
    (0, vitest_1.expect)((0, bytes_js_1.binaryToInteger)("110100101000010101")).toBe(215573);
});
(0, vitest_1.test)("byteToBits()", () => {
    (0, vitest_1.expect)((0, bytes_js_1.byteToBinary)(101)).toBe("01100101");
});
(0, vitest_1.test)("bytesToBits()", () => {
    (0, vitest_1.expect)((0, bytes_js_1.bytesToBinary)(new Uint8Array([203, 3, 41, 76]))).toBe("11001011000000110010100101001100");
});
(0, vitest_1.test)("bytesToInteger()", () => {
    const bytes = Uint8Array.from([54, 204, 4, 128]);
    (0, vitest_1.expect)((0, bytes_js_1.bytesToInteger)(bytes)).toBe(new DataView(bytes.buffer).getUint32(0));
});
(0, vitest_1.test)("compareBytes()", () => {
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    (0, vitest_1.expect)((0, bytes_js_1.compareBytes)(randomBytes, randomBytes)).toBe(true);
    const anotherRandomBytes = new Uint8Array(32);
    crypto.getRandomValues(anotherRandomBytes);
    (0, vitest_1.expect)((0, bytes_js_1.compareBytes)(randomBytes, anotherRandomBytes)).toBe(false);
});
