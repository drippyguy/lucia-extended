"use strict";
var import_index = require("./index.cjs");
var import_vitest = require("vitest");
(0, import_vitest.describe)("serializeCookie()", () => {
  (0, import_vitest.test)("serializes cookie", () => {
    const currDate = /* @__PURE__ */ new Date();
    const expected = `message=hello; Domain=example.com; Expires=${currDate.toUTCString()}; HttpOnly; Max-Age=60; Path=/foo; SameSite=Lax; Secure`;
    const result = (0, import_index.serializeCookie)("message", "hello", {
      domain: "example.com",
      expires: currDate,
      httpOnly: true,
      maxAge: 60,
      path: "/foo",
      sameSite: "lax",
      secure: true
    });
    (0, import_vitest.expect)(result).toBe(expected);
  });
  (0, import_vitest.test)("escapes name and value", () => {
    const expected = `%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C=%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C`;
    const result = (0, import_index.serializeCookie)(
      " -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\",
      " -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\",
      {}
    );
    (0, import_vitest.expect)(result).toBe(expected);
  });
});
(0, import_vitest.describe)("parseCookies()", () => {
  (0, import_vitest.test)("parse cookie header", () => {
    const cookies = (0, import_index.parseCookies)("message1=hello; message2=bye");
    (0, import_vitest.expect)(cookies.get("message1")).toBe("hello");
    (0, import_vitest.expect)(cookies.get("message2")).toBe("bye");
    (0, import_vitest.expect)(cookies.get("message3")).toBe(void 0);
  });
  (0, import_vitest.test)("reads empty value", () => {
    const cookies = (0, import_index.parseCookies)("message1=; message2");
    (0, import_vitest.expect)(cookies.get("message1")).toBe("");
    (0, import_vitest.expect)(cookies.get("message2")).toBe("");
  });
  (0, import_vitest.test)("decodes escaped name and values", () => {
    const cookies = (0, import_index.parseCookies)(
      `%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C=%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C`
    );
    (0, import_vitest.expect)(cookies.get(" -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\")).toBe(
      " -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\"
    );
  });
});
//# sourceMappingURL=index.test.cjs.map