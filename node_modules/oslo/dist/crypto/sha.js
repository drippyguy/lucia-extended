"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha512 = exports.sha384 = exports.sha256 = exports.sha1 = void 0;
async function sha1(data) {
    return await crypto.subtle.digest("SHA-1", data);
}
exports.sha1 = sha1;
async function sha256(data) {
    return await crypto.subtle.digest("SHA-256", data);
}
exports.sha256 = sha256;
async function sha384(data) {
    return await crypto.subtle.digest("SHA-384", data);
}
exports.sha384 = sha384;
async function sha512(data) {
    return await crypto.subtle.digest("SHA-512", data);
}
exports.sha512 = sha512;
