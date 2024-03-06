"use strict";
var import_vitest = require("vitest");
var import_index = require("./index.cjs");
var import_node_crypto = require("node:crypto");
var import_crypto = require("oslo/crypto");
var import_encoding = require("oslo/encoding");
(0, import_vitest.test)("scrypt() output matches crypto", async () => {
  const password = (0, import_crypto.generateRandomString)(16, (0, import_crypto.alphabet)("a-z", "A-Z", "0-9"));
  const salt = (0, import_encoding.encodeHex)(crypto.getRandomValues(new Uint8Array(16)));
  const scryptHash = await (0, import_index.scrypt)(
    new TextEncoder().encode(password),
    new TextEncoder().encode(salt),
    {
      N: 16384,
      r: 16,
      p: 1,
      dkLen: 64
    }
  );
  const cryptoHash = new Uint8Array(
    (0, import_node_crypto.scryptSync)(password, salt, 64, {
      N: 16384,
      p: 1,
      r: 16,
      maxmem: 128 * 16384 * 16 * 2
    }).buffer
  );
  (0, import_vitest.expect)(cryptoHash).toStrictEqual(scryptHash);
});
//# sourceMappingURL=index.test.cjs.map