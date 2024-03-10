"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = require("./index.js");
const vitest_1 = require("vitest");
(0, vitest_1.describe)("verifyRequestOrigin()", () => {
    (0, vitest_1.test)("checks if origin and host matches", () => {
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.com", ["example.com"])).toBe(true);
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.co.jp", ["example.co.jp"])).toBe(true);
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.com", ["invalid.com"])).toBe(false);
    });
    (0, vitest_1.test)("allows full urls for host", () => {
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.com", ["https://example.com"])).toBe(true);
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.co.jp", ["https://example.co.jp"])).toBe(true);
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.com", ["https://invalid.com"])).toBe(false);
    });
    (0, vitest_1.test)("checks port", () => {
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.com:1000", ["example.com:1000"])).toBe(true);
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("https://example.com:1000", ["example.com:2000"])).toBe(false);
    });
    (0, vitest_1.test)("IDN", () => {
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("http://xn--zckzah.com", ["xn--zckzah.com"])).toBe(true);
        (0, vitest_1.expect)((0, index_js_1.verifyRequestOrigin)("http://xn--zckzah.com", ["テスト.com"])).toBe(true);
    });
});
