"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = require("./index.js");
const vitest_1 = require("vitest");
(0, vitest_1.describe)("serializeCookie()", () => {
    (0, vitest_1.test)("serializes cookie", () => {
        const currDate = new Date();
        const expected = `message=hello; Domain=example.com; Expires=${currDate.toUTCString()}; HttpOnly; Max-Age=60; Path=/foo; SameSite=Lax; Secure`;
        const result = (0, index_js_1.serializeCookie)("message", "hello", {
            domain: "example.com",
            expires: currDate,
            httpOnly: true,
            maxAge: 60,
            path: "/foo",
            sameSite: "lax",
            secure: true
        });
        (0, vitest_1.expect)(result).toBe(expected);
    });
    (0, vitest_1.test)("escapes name and value", () => {
        const expected = `%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C=%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C`;
        const result = (0, index_js_1.serializeCookie)(" -^¥@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\", " -^¥@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\", {});
        (0, vitest_1.expect)(result).toBe(expected);
    });
});
(0, vitest_1.describe)("parseCookies()", () => {
    (0, vitest_1.test)("parse cookie header", () => {
        const cookies = (0, index_js_1.parseCookies)("message1=hello; message2=bye");
        (0, vitest_1.expect)(cookies.get("message1")).toBe("hello");
        (0, vitest_1.expect)(cookies.get("message2")).toBe("bye");
        (0, vitest_1.expect)(cookies.get("message3")).toBe(undefined);
    });
    (0, vitest_1.test)("reads empty value", () => {
        const cookies = (0, index_js_1.parseCookies)("message1=; message2");
        (0, vitest_1.expect)(cookies.get("message1")).toBe("");
        (0, vitest_1.expect)(cookies.get("message2")).toBe("");
    });
    (0, vitest_1.test)("decodes escaped name and values", () => {
        const cookies = (0, index_js_1.parseCookies)(`%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C=%20-%5E%C2%A5%40%5B%3B%3A%5D%2C.%2F_!%22%23%24%25%26'()0%3D~%7C%60%7B%2B*%7D%3C%3E%3F%5C`);
        (0, vitest_1.expect)(cookies.get(" -^¥@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\")).toBe(" -^¥@[;:],./_!\"#$%&'()0=~|`{+*}<>?\\");
    });
});
