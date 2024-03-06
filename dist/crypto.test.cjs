"use strict";
var import_vitest = require("vitest");
var import_crypto = require("./crypto.cjs");
var import_encoding = require("oslo/encoding");
(0, import_vitest.test)("validateScryptHash() validates hashes generated with generateScryptHash()", async () => {
  const password = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
  const scrypt = new import_crypto.Scrypt();
  const hash = await scrypt.hash(password);
  await (0, import_vitest.expect)(scrypt.verify(hash, password)).resolves.toBe(true);
  const falsePassword = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
  await (0, import_vitest.expect)(scrypt.verify(hash, falsePassword)).resolves.toBe(false);
});
(0, import_vitest.test)("LegacyScrypt", async () => {
  const password = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
  const scrypt = new import_crypto.LegacyScrypt();
  const hash = await scrypt.hash(password);
  await (0, import_vitest.expect)(scrypt.verify(hash, password)).resolves.toBe(true);
  const falsePassword = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
  await (0, import_vitest.expect)(scrypt.verify(hash, falsePassword)).resolves.toBe(false);
});
//# sourceMappingURL=crypto.test.cjs.map