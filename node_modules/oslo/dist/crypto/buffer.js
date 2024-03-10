"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.constantTimeEqual = void 0;
function constantTimeEqual(a, b) {
    const aBuffer = new Uint8Array(a);
    const bBuffer = new Uint8Array(b);
    if (aBuffer.length !== bBuffer.length) {
        return false;
    }
    let c = 0;
    for (let i = 0; i < aBuffer.length; i++) {
        c |= aBuffer[i] ^ bBuffer[i]; // ^: XOR operator
    }
    return c === 0;
}
exports.constantTimeEqual = constantTimeEqual;
