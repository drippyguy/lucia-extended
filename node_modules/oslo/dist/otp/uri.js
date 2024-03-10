"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createHOTPKeyURI = exports.createTOTPKeyURI = void 0;
const index_js_1 = require("../encoding/index.js");
function createTOTPKeyURI(issuer, accountName, secret, options) {
    const [baseURI, params] = createKeyURIBase("totp", issuer, accountName, secret, options);
    if (options?.period !== undefined) {
        params.set("period", options.period.seconds().toString());
    }
    return baseURI + "?" + params.toString();
}
exports.createTOTPKeyURI = createTOTPKeyURI;
function createHOTPKeyURI(issuer, accountName, secret, options) {
    const [baseURI, params] = createKeyURIBase("hotp", issuer, accountName, secret, options);
    const counter = options?.counter ?? 0;
    params.set("counter", counter.toString());
    return baseURI + "?" + params.toString();
}
exports.createHOTPKeyURI = createHOTPKeyURI;
function createKeyURIBase(type, issuer, accountName, secret, options) {
    const encodedIssuer = encodeURIComponent(issuer);
    const encodedAccountName = encodeURIComponent(accountName);
    const baseURI = `otpauth://${type}/${encodedIssuer}:${encodedAccountName}`;
    const params = new URLSearchParams({
        secret: index_js_1.base32.encode(new Uint8Array(secret), {
            includePadding: false
        }),
        issuer: encodedIssuer
    });
    if (options?.digits !== undefined) {
        params.set("digits", options.digits.toString());
    }
    return [baseURI, params];
}
