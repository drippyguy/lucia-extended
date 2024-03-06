"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeBase64url = exports.encodeBase64url = exports.decodeBase64 = exports.encodeBase64 = exports.base64url = exports.base64 = exports.Base64Encoding = void 0;
class Base64Encoding {
    constructor(alphabet, options) {
        this.decodeMap = new Map();
        if (alphabet.length !== 64) {
            throw new Error("Invalid alphabet");
        }
        this.alphabet = alphabet;
        this.padding = options?.padding ?? "=";
        if (this.alphabet.includes(this.padding) || this.padding.length !== 1) {
            throw new Error("Invalid padding");
        }
        for (let i = 0; i < alphabet.length; i++) {
            this.decodeMap.set(alphabet[i], i);
        }
    }
    encode(data, options) {
        let result = "";
        let buffer = 0;
        let shift = 0;
        for (let i = 0; i < data.length; i++) {
            buffer = (buffer << 8) | data[i];
            shift += 8;
            while (shift >= 6) {
                shift += -6;
                result += this.alphabet[(buffer >> shift) & 0x3f];
            }
        }
        if (shift > 0) {
            result += this.alphabet[(buffer << (6 - shift)) & 0x3f];
        }
        const includePadding = options?.includePadding ?? true;
        if (includePadding) {
            const padCount = (4 - (result.length % 4)) % 4;
            for (let i = 0; i < padCount; i++) {
                result += "=";
            }
        }
        return result;
    }
    decode(data, options) {
        const strict = options?.strict ?? true;
        const chunkCount = Math.ceil(data.length / 4);
        const result = [];
        for (let i = 0; i < chunkCount; i++) {
            let padCount = 0;
            let buffer = 0;
            for (let j = 0; j < 4; j++) {
                const encoded = data[i * 4 + j];
                if (encoded === "=") {
                    if (i + 1 !== chunkCount) {
                        throw new Error(`Invalid character: ${encoded}`);
                    }
                    padCount += 1;
                    continue;
                }
                if (encoded === undefined) {
                    if (strict) {
                        throw new Error("Invalid data");
                    }
                    padCount += 1;
                    continue;
                }
                const value = this.decodeMap.get(encoded) ?? null;
                if (value === null) {
                    throw new Error(`Invalid character: ${encoded}`);
                }
                buffer += value << (6 * (3 - j));
            }
            result.push((buffer >> 16) & 0xff);
            if (padCount < 2) {
                result.push((buffer >> 8) & 0xff);
            }
            if (padCount < 1) {
                result.push(buffer & 0xff);
            }
        }
        return Uint8Array.from(result);
    }
}
exports.Base64Encoding = Base64Encoding;
exports.base64 = new Base64Encoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
exports.base64url = new Base64Encoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
/** @deprecated Use `base64.encode()` instead */
function encodeBase64(data, options) {
    return exports.base64.encode(new Uint8Array(data), {
        includePadding: options?.padding ?? true
    });
}
exports.encodeBase64 = encodeBase64;
/** @deprecated Use `base64.decode()` instead */
function decodeBase64(data) {
    return exports.base64.decode(data, {
        strict: false
    });
}
exports.decodeBase64 = decodeBase64;
/** @deprecated Use `base64url.encode()` instead */
function encodeBase64url(data) {
    return exports.base64.encode(new Uint8Array(data), {
        includePadding: false
    });
}
exports.encodeBase64url = encodeBase64url;
/** @deprecated Use `base64url.decode()` instead */
function decodeBase64url(data) {
    return exports.base64url.decode(data, {
        strict: false
    });
}
exports.decodeBase64url = decodeBase64url;
