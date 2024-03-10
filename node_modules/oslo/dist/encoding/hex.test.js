"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const hex_js_1 = require("./hex.js");
(0, vitest_1.describe)("encodeHex()", () => {
    (0, vitest_1.test)("Generates valid hex string", () => {
        const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for (const length of cases) {
            const data = crypto.getRandomValues(new Uint8Array(length));
            (0, vitest_1.expect)((0, hex_js_1.encodeHex)(data)).toBe(Buffer.from(data).toString("hex"));
        }
    });
});
(0, vitest_1.describe)("Base32.decode()", () => {
    (0, vitest_1.test)("Returns encoded data", () => {
        const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for (const length of cases) {
            const data = crypto.getRandomValues(new Uint8Array(length));
            const encoded = (0, hex_js_1.encodeHex)(data);
            (0, vitest_1.expect)((0, hex_js_1.decodeHex)(encoded)).toStrictEqual(data);
            (0, vitest_1.expect)((0, hex_js_1.decodeHex)(encoded.toUpperCase())).toStrictEqual(data);
        }
    });
    (0, vitest_1.test)("Throws if data is invalid", () => {
        (0, vitest_1.expect)(() => (0, hex_js_1.decodeHex)("a")).toThrow();
    });
});
