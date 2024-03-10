"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Argon2id = void 0;
const argon2_1 = require("@node-rs/argon2");
const v0x13 = 1;
class Argon2id {
    constructor(options) {
        this.memorySize = options?.memorySize ?? 19456;
        this.iterations = options?.iterations ?? 2;
        this.tagLength = options?.tagLength ?? 32;
        this.parallelism = options?.parallelism ?? 1;
        this.secret = options?.secret ?? null;
    }
    async hash(password) {
        return await (0, argon2_1.hash)(password.normalize("NFKC"), {
            memoryCost: this.memorySize,
            timeCost: this.iterations,
            outputLen: this.tagLength,
            parallelism: this.parallelism,
            version: v0x13,
            secret: this.secret ? Buffer.from(this.secret) : undefined
        });
    }
    async verify(hash, password) {
        return await (0, argon2_1.verify)(hash, password.normalize("NFKC"), {
            memoryCost: this.memorySize,
            timeCost: this.iterations,
            outputLen: this.tagLength,
            parallelism: this.parallelism,
            version: v0x13,
            secret: this.secret ? Buffer.from(this.secret) : undefined
        });
    }
}
exports.Argon2id = Argon2id;
