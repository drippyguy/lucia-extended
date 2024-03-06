"use strict";
var import_vitest = require("vitest");
var import_index = require("./index.cjs");
var import_encoding = require("../encoding/index.cjs");
(0, import_vitest.test)("Argon2id", async () => {
  const password = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
  const argon2id = new import_index.Argon2id();
  const hash = await argon2id.hash(password);
  (0, import_vitest.expect)(argon2id.verify(hash, password)).resolves.toBe(true);
});
(0, import_vitest.test)("Bcrypt", async () => {
  const password = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
  const bcrypt = new import_index.Bcrypt();
  const hash = await bcrypt.hash(password);
  (0, import_vitest.expect)(bcrypt.verify(hash, password)).resolves.toBe(true);
});
(0, import_vitest.test)("Argon2id", async () => {
  const password = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
  const scrypt = new import_index.Scrypt();
  const hash = await scrypt.hash(password);
  (0, import_vitest.expect)(scrypt.verify(hash, password)).resolves.toBe(true);
});
//# sourceMappingURL=index.test.cjs.map