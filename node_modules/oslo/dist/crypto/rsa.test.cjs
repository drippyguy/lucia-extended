"use strict";
var import_vitest = require("vitest");
var import_rsa = require("./rsa.cjs");
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
import_vitest.describe.each(testCases)("RSASSAPKCS1v1_5($hash)", ({ hash }) => {
  (0, import_vitest.test)("Creates and verifies signature", async () => {
    const rsa = new import_rsa.RSASSAPKCS1v1_5(hash);
    const data = new TextEncoder().encode("Hello world!");
    const { publicKey, privateKey } = await rsa.generateKeyPair();
    const signature = await rsa.sign(privateKey, data);
    await (0, import_vitest.expect)(rsa.verify(publicKey, signature, data)).resolves.toBe(true);
  });
  (0, import_vitest.test)("Fails on invalid signature", async () => {
    const rsa = new import_rsa.RSASSAPKCS1v1_5(hash);
    const data = new TextEncoder().encode("Hello world!");
    const keyPairA = await rsa.generateKeyPair();
    const signature = await rsa.sign(keyPairA.privateKey, data);
    const keyPairB = await rsa.generateKeyPair();
    await (0, import_vitest.expect)(rsa.verify(keyPairB.publicKey, signature, data)).resolves.toBe(false);
  });
});
import_vitest.describe.each(testCases)("RSASSAPSS($hash)", ({ hash }) => {
  (0, import_vitest.test)("Creates and verifies signature", async () => {
    const rsa = new import_rsa.RSASSAPSS(hash);
    const data = new TextEncoder().encode("Hello world!");
    const { publicKey, privateKey } = await rsa.generateKeyPair();
    const signature = await rsa.sign(privateKey, data);
    await (0, import_vitest.expect)(rsa.verify(publicKey, signature, data)).resolves.toBe(true);
  });
  (0, import_vitest.test)("Fails on invalid signature", async () => {
    const rsa = new import_rsa.RSASSAPKCS1v1_5(hash);
    const data = new TextEncoder().encode("Hello world!");
    const keyPairA = await rsa.generateKeyPair();
    const signature = await rsa.sign(keyPairA.privateKey, data);
    const keyPairB = await rsa.generateKeyPair();
    await (0, import_vitest.expect)(rsa.verify(keyPairB.publicKey, signature, data)).resolves.toBe(false);
  });
});
//# sourceMappingURL=rsa.test.cjs.map