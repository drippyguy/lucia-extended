"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const index_js_1 = require("./index.js");
const index_js_2 = require("../encoding/index.js");
(0, vitest_1.test)("Argon2id", async () => {
    const password = (0, index_js_2.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
    const argon2id = new index_js_1.Argon2id();
    const hash = await argon2id.hash(password);
    (0, vitest_1.expect)(argon2id.verify(hash, password)).resolves.toBe(true);
});
(0, vitest_1.test)("Bcrypt", async () => {
    const password = (0, index_js_2.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
    const bcrypt = new index_js_1.Bcrypt();
    const hash = await bcrypt.hash(password);
    (0, vitest_1.expect)(bcrypt.verify(hash, password)).resolves.toBe(true);
});
(0, vitest_1.test)("Argon2id", async () => {
    const password = (0, index_js_2.encodeHex)(crypto.getRandomValues(new Uint8Array(32)));
    const scrypt = new index_js_1.Scrypt();
    const hash = await scrypt.hash(password);
    (0, vitest_1.expect)(scrypt.verify(hash, password)).resolves.toBe(true);
});
