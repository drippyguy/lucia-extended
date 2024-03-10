"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Scrypt = void 0;
const node_crypto_1 = require("node:crypto");
const index_js_1 = require("../encoding/index.js");
const index_js_2 = require("../crypto/index.js");
class Scrypt {
    constructor(options) {
        this.N = options?.N ?? 16384;
        this.r = options?.r ?? 16;
        this.p = options?.p ?? 1;
        this.dkLen = options?.dkLen ?? 64;
    }
    async hash(password) {
        const salt = (0, index_js_1.encodeHex)(crypto.getRandomValues(new Uint8Array(16)));
        const key = await this.generateKey(password, salt);
        return `${salt}:${(0, index_js_1.encodeHex)(key)}`;
    }
    async verify(hash, password) {
        const [salt, key] = hash.split(":");
        const targetKey = await this.generateKey(password, salt);
        return (0, index_js_2.constantTimeEqual)(targetKey, (0, index_js_1.decodeHex)(key));
    }
    async generateKey(password, salt) {
        return await new Promise((resolve, reject) => {
            (0, node_crypto_1.scrypt)(password.normalize("NFKC"), salt, this.dkLen, {
                N: this.N,
                p: this.p,
                r: this.r,
                // errors when 128 * N * r > `maxmem` (approximately)
                maxmem: 128 * this.N * this.r * 2
            }, (err, buff) => {
                if (err)
                    return reject(err);
                return resolve(buff);
            });
        });
    }
}
exports.Scrypt = Scrypt;
