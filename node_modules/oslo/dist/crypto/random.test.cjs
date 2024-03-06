"use strict";
var import_vitest = require("vitest");
var import_random = require("./random.cjs");
(0, import_vitest.test)("alphabet()", async () => {
  (0, import_vitest.expect)((0, import_random.alphabet)("0-9", "a-z", "A-Z", "-", "_")).toBe(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
  );
});
//# sourceMappingURL=random.test.cjs.map