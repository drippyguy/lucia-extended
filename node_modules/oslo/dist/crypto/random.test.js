"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const random_js_1 = require("./random.js");
(0, vitest_1.test)("alphabet()", async () => {
    (0, vitest_1.expect)((0, random_js_1.alphabet)("0-9", "a-z", "A-Z", "-", "_")).toBe("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_");
});
