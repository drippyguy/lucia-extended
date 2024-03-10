"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TOTPController = void 0;
const index_js_1 = require("../index.js");
const hotp_js_1 = require("./hotp.js");
class TOTPController {
    constructor(options) {
        this.digits = options?.digits ?? 6;
        this.period = options?.period ?? new index_js_1.TimeSpan(30, "s");
    }
    async generate(secret) {
        const counter = Math.floor(Date.now() / this.period.milliseconds());
        return await (0, hotp_js_1.generateHOTP)(secret, counter, this.digits);
    }
    async verify(totp, secret) {
        const expectedTOTP = await this.generate(secret);
        return totp === expectedTOTP;
    }
}
exports.TOTPController = TOTPController;
