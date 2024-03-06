"use strict";
var import_vitest = require("vitest");
var import_index = require("./index.cjs");
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
import_vitest.describe.each(testCases)("HMAC($hash)", ({ hash }) => {
  (0, import_vitest.test)("Creates and verifies signature", async () => {
    const hmac = new import_index.HMAC(hash);
    const data = new TextEncoder().encode("Hello world!");
    const key = await hmac.generateKey();
    const signature = await hmac.sign(key, data);
    await (0, import_vitest.expect)(hmac.verify(key, signature, data)).resolves.toBe(true);
  });
  (0, import_vitest.test)("Fails on invalid signature", async () => {
    const hmac = new import_index.HMAC(hash);
    const data = new TextEncoder().encode("Hello world!");
    const keyA = await hmac.generateKey();
    const signature = await hmac.sign(keyA, data);
    const keyB = await hmac.generateKey();
    await (0, import_vitest.expect)(hmac.verify(keyB, signature, data)).resolves.toBe(false);
  });
});
//# sourceMappingURL=hmac.test.cjs.map