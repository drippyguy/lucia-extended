"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const rsa_js_1 = require("./rsa.js");
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
vitest_1.describe.each(testCases)("RSASSAPKCS1v1_5($hash)", ({ hash }) => {
    (0, vitest_1.test)("Creates and verifies signature", async () => {
        const rsa = new rsa_js_1.RSASSAPKCS1v1_5(hash);
        const data = new TextEncoder().encode("Hello world!");
        const { publicKey, privateKey } = await rsa.generateKeyPair();
        const signature = await rsa.sign(privateKey, data);
        await (0, vitest_1.expect)(rsa.verify(publicKey, signature, data)).resolves.toBe(true);
    });
    (0, vitest_1.test)("Fails on invalid signature", async () => {
        const rsa = new rsa_js_1.RSASSAPKCS1v1_5(hash);
        const data = new TextEncoder().encode("Hello world!");
        const keyPairA = await rsa.generateKeyPair();
        const signature = await rsa.sign(keyPairA.privateKey, data);
        const keyPairB = await rsa.generateKeyPair();
        await (0, vitest_1.expect)(rsa.verify(keyPairB.publicKey, signature, data)).resolves.toBe(false);
    });
});
vitest_1.describe.each(testCases)("RSASSAPSS($hash)", ({ hash }) => {
    (0, vitest_1.test)("Creates and verifies signature", async () => {
        const rsa = new rsa_js_1.RSASSAPSS(hash);
        const data = new TextEncoder().encode("Hello world!");
        const { publicKey, privateKey } = await rsa.generateKeyPair();
        const signature = await rsa.sign(privateKey, data);
        await (0, vitest_1.expect)(rsa.verify(publicKey, signature, data)).resolves.toBe(true);
    });
    (0, vitest_1.test)("Fails on invalid signature", async () => {
        const rsa = new rsa_js_1.RSASSAPKCS1v1_5(hash);
        const data = new TextEncoder().encode("Hello world!");
        const keyPairA = await rsa.generateKeyPair();
        const signature = await rsa.sign(keyPairA.privateKey, data);
        const keyPairB = await rsa.generateKeyPair();
        await (0, vitest_1.expect)(rsa.verify(keyPairB.publicKey, signature, data)).resolves.toBe(false);
    });
});
