import { serializeCookie, parseCookies } from "./index.js";
import { describe, test, expect } from "vitest";
describe("serializeCookie()", () => {
  test("serializes cookie", () => {
    const currDate = /* @__PURE__ */ new Date();
    const expected = `message=hello; Domain=example.com; Expires=${currDate.toUTCString()}; HttpOnly; Max-Age=60; Path=/foo; SameSite=Lax; Secure`;
    const result = serializeCookie("message", "hello", {
      domain: "example.com",
      expires: currDate,
      httpOnly: true,
      maxAge: 60,
      path: "/foo",
      sameSite: "lax",
      secure: true
    });
    expect(result).toBe(expected);
  });
  test("escapes name and value", () => {
    const expected = `%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C=%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C`;
    const result = serializeCookie(
      " -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\",
      " -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\",
      {}
    );
    expect(result).toBe(expected);
  });
});
describe("parseCookies()", () => {
  test("parse cookie header", () => {
    const cookies = parseCookies("message1=hello; message2=bye");
    expect(cookies.get("message1")).toBe("hello");
    expect(cookies.get("message2")).toBe("bye");
    expect(cookies.get("message3")).toBe(void 0);
  });
  test("reads empty value", () => {
    const cookies = parseCookies("message1=; message2");
    expect(cookies.get("message1")).toBe("");
    expect(cookies.get("message2")).toBe("");
  });
  test("decodes escaped name and values", () => {
    const cookies = parseCookies(
      `%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C=%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C`
    );
    expect(cookies.get(" -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\")).toBe(
      " -^\xA5@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\"
    );
  });
});
//# sourceMappingURL=index.test.js.map