"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const index_js_1 = require("./index.js");
const testCases = [
    {
        hash: "SHA-1",
        curve: "P-256"
    },
    {
        hash: "SHA-256",
        curve: "P-256"
    },
    {
        hash: "SHA-384",
        curve: "P-384"
    },
    {
        hash: "SHA-512",
        curve: "P-521"
    }
];
vitest_1.describe.each(testCases)("ECDSA($hash, $curve)", ({ hash, curve }) => {
    (0, vitest_1.test)("Creates and verifies signature", async () => {
        const ecdsa = new index_js_1.ECDSA(hash, curve);
        const data = new TextEncoder().encode("Hello world!");
        const { publicKey, privateKey } = await ecdsa.generateKeyPair();
        const signature = await ecdsa.sign(privateKey, data);
        await (0, vitest_1.expect)(ecdsa.verify(publicKey, signature, data)).resolves.toBe(true);
    });
    (0, vitest_1.test)("Fails on invalid signature", async () => {
        const ecdsa = new index_js_1.ECDSA(hash, curve);
        const data = new TextEncoder().encode("Hello world!");
        const keyPairA = await ecdsa.generateKeyPair();
        const signature = await ecdsa.sign(keyPairA.privateKey, data);
        const keyPairB = await ecdsa.generateKeyPair();
        await (0, vitest_1.expect)(ecdsa.verify(keyPairB.publicKey, signature, data)).resolves.toBe(false);
    });
});
