"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const base_1 = require("@scure/base");
const base32_js_1 = require("./base32.js");
(0, vitest_1.describe)("Base32.encode()", () => {
    (0, vitest_1.test)("Generates valid string", () => {
        const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for (const length of cases) {
            const data = crypto.getRandomValues(new Uint8Array(length));
            (0, vitest_1.expect)(base32_js_1.base32.encode(data)).toBe(base_1.base32.encode(data));
        }
    });
    (0, vitest_1.test)("Omits padding", () => {
        const data = crypto.getRandomValues(new Uint8Array(4));
        const result = base32_js_1.base32.encode(data, {
            includePadding: false
        });
        const expected = base32_js_1.base32.encode(data).replaceAll("=", "");
        (0, vitest_1.expect)(result).toBe(expected);
    });
});
(0, vitest_1.describe)("Base32.decode()", () => {
    (0, vitest_1.test)("Returns encoded data", () => {
        const cases = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for (const length of cases) {
            const data = crypto.getRandomValues(new Uint8Array(length));
            const encoded = base32_js_1.base32.encode(data);
            (0, vitest_1.expect)(base32_js_1.base32.decode(encoded)).toStrictEqual(data);
        }
    });
    (0, vitest_1.test)("Throws if data is missing padding in strict mode", () => {
        const data = crypto.getRandomValues(new Uint8Array(4));
        const encoded = base32_js_1.base32.encode(data, {
            includePadding: false
        });
        (0, vitest_1.expect)(() => base32_js_1.base32.decode(encoded.replaceAll("=", ""))).toThrow();
    });
    (0, vitest_1.test)("Accepts encoded data with missing padding if not in strict mode", () => {
        const data = crypto.getRandomValues(new Uint8Array(4));
        const encoded = base32_js_1.base32.encode(data, {
            includePadding: false
        });
        const result = base32_js_1.base32.decode(encoded.replaceAll("=", ""), {
            strict: false
        });
        (0, vitest_1.expect)(result).toStrictEqual(data);
    });
});
