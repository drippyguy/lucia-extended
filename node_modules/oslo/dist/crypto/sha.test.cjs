"use strict";
var import_vitest = require("vitest");
var import_sha = require("./sha.cjs");
var import_encoding = require("../encoding/index.cjs");
const data = new TextEncoder().encode("hello world");
(0, import_vitest.test)("sha1()", async () => {
  const result = await (0, import_sha.sha1)(data);
  (0, import_vitest.expect)((0, import_encoding.encodeHex)(result)).toBe("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
});
(0, import_vitest.test)("sha256()", async () => {
  const result = await (0, import_sha.sha256)(data);
  (0, import_vitest.expect)((0, import_encoding.encodeHex)(result)).toBe(
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  );
});
(0, import_vitest.test)("sha384()", async () => {
  const result = await (0, import_sha.sha384)(data);
  (0, import_vitest.expect)((0, import_encoding.encodeHex)(result)).toBe(
    "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
  );
});
(0, import_vitest.test)("sha512()", async () => {
  const result = await (0, import_sha.sha512)(data);
  (0, import_vitest.expect)((0, import_encoding.encodeHex)(result)).toBe(
    "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
  );
});
//# sourceMappingURL=sha.test.cjs.map