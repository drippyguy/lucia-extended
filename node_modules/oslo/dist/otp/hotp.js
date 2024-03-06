"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateHOTP = void 0;
const bytes_js_1 = require("../bytes.js");
const hmac_js_1 = require("../crypto/hmac.js");
async function generateHOTP(key, counter, digits = 6) {
    if (digits > 8) {
        throw new TypeError("Digits must be 8 or smaller");
    }
    const counterBytes = intTo8Bytes(counter);
    const HS = await new hmac_js_1.HMAC("SHA-1").sign(key, counterBytes);
    const SBites = truncate(new Uint8Array(HS));
    const SNum = (0, bytes_js_1.binaryToInteger)(SBites);
    const D = SNum % 10 ** digits;
    return D.toString().padStart(digits, "0");
}
exports.generateHOTP = generateHOTP;
function truncate(data) {
    const offset = (0, bytes_js_1.binaryToInteger)((0, bytes_js_1.byteToBinary)(data[data.byteLength - 1]).slice(4));
    return (0, bytes_js_1.bytesToBinary)(data).slice(offset * 8 + 1, (offset + 4) * 8);
}
function intTo8Bytes(int) {
    const result = new Uint8Array(8);
    const bits = int.toString(2).padStart(8 * 8, "0");
    for (let i = 0; i < 8; i++) {
        result[i] = (0, bytes_js_1.binaryToInteger)(bits.slice(i * 8, (i + 1) * 8));
    }
    return result;
}
