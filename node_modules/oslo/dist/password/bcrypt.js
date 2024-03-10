"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Bcrypt = void 0;
const bcrypt_1 = require("@node-rs/bcrypt");
class Bcrypt {
    constructor(options) {
        this.cost = options?.cost ?? 10;
    }
    async hash(password) {
        return await (0, bcrypt_1.hash)(password.normalize("NFKC"), this.cost);
    }
    async verify(hash, password) {
        return await (0, bcrypt_1.verify)(password.normalize("NFKC"), hash);
    }
}
exports.Bcrypt = Bcrypt;
