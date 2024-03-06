"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const index_js_1 = require("./index.js");
const testCases = [
    {
        hash: "SHA-1"
    },
    {
        hash: "SHA-256"
    },
    {
        hash: "SHA-384"
    },
    {
        hash: "SHA-512"
    }
];
vitest_1.describe.each(testCases)("HMAC($hash)", ({ hash }) => {
    (0, vitest_1.test)("Creates and verifies signature", async () => {
        const hmac = new index_js_1.HMAC(hash);
        const data = new TextEncoder().encode("Hello world!");
        const key = await hmac.generateKey();
        const signature = await hmac.sign(key, data);
        await (0, vitest_1.expect)(hmac.verify(key, signature, data)).resolves.toBe(true);
    });
    (0, vitest_1.test)("Fails on invalid signature", async () => {
        const hmac = new index_js_1.HMAC(hash);
        const data = new TextEncoder().encode("Hello world!");
        const keyA = await hmac.generateKey();
        const signature = await hmac.sign(keyA, data);
        const keyB = await hmac.generateKey();
        await (0, vitest_1.expect)(hmac.verify(keyB, signature, data)).resolves.toBe(false);
    });
});
