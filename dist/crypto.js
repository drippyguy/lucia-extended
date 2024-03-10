"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LegacyScrypt = exports.Scrypt = exports.generateId = void 0;
const encoding_1 = require("oslo/encoding");
const crypto_1 = require("oslo/crypto");
const index_js_1 = require("./scrypt/index.js");
async function generateScryptKey(data, salt, blockSize = 16) {
    const encodedData = new TextEncoder().encode(data);
    const encodedSalt = new TextEncoder().encode(salt);
    const keyUint8Array = await (0, index_js_1.scrypt)(encodedData, encodedSalt, {
        N: 16384,
        r: blockSize,
        p: 1,
        dkLen: 64
    });
    return keyUint8Array;
}
function generateId(length) {
    return (0, crypto_1.generateRandomString)(length, (0, crypto_1.alphabet)("0-9", "a-z"));
}
exports.generateId = generateId;
class Scrypt {
    async hash(password) {
        const salt = (0, encoding_1.encodeHex)(crypto.getRandomValues(new Uint8Array(16)));
        const key = await generateScryptKey(password.normalize("NFKC"), salt);
        return `${salt}:${(0, encoding_1.encodeHex)(key)}`;
    }
    async verify(hash, password) {
        const parts = hash.split(":");
        if (parts.length !== 2)
            return false;
        const [salt, key] = parts;
        const targetKey = await generateScryptKey(password.normalize("NFKC"), salt);
        return (0, crypto_1.constantTimeEqual)(targetKey, (0, encoding_1.decodeHex)(key));
    }
}
exports.Scrypt = Scrypt;
class LegacyScrypt {
    async hash(password) {
        const salt = (0, encoding_1.encodeHex)(crypto.getRandomValues(new Uint8Array(16)));
        const key = await generateScryptKey(password.normalize("NFKC"), salt);
        return `s2:${salt}:${(0, encoding_1.encodeHex)(key)}`;
    }
    async verify(hash, password) {
        const parts = hash.split(":");
        if (parts.length === 2) {
            const [salt, key] = parts;
            const targetKey = await generateScryptKey(password.normalize("NFKC"), salt, 8);
            const result = (0, crypto_1.constantTimeEqual)(targetKey, (0, encoding_1.decodeHex)(key));
            return result;
        }
        if (parts.length !== 3)
            return false;
        const [version, salt, key] = parts;
        if (version === "s2") {
            const targetKey = await generateScryptKey(password.normalize("NFKC"), salt);
            return (0, crypto_1.constantTimeEqual)(targetKey, (0, encoding_1.decodeHex)(key));
        }
        return false;
    }
}
exports.LegacyScrypt = LegacyScrypt;
