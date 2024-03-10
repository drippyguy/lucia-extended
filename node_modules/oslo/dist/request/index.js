"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyRequestOrigin = void 0;
function verifyRequestOrigin(origin, allowedDomains) {
    if (!origin || allowedDomains.length === 0)
        return false;
    const originHost = safeURL(origin)?.host ?? null;
    if (!originHost)
        return false;
    for (const domain of allowedDomains) {
        let host;
        if (domain.startsWith("http://") || domain.startsWith("https://")) {
            host = safeURL(domain)?.host ?? null;
        }
        else {
            host = safeURL("https://" + domain)?.host ?? null;
        }
        if (originHost === host)
            return true;
    }
    return false;
}
exports.verifyRequestOrigin = verifyRequestOrigin;
function safeURL(url) {
    try {
        return new URL(url);
    }
    catch {
        return null;
    }
}
