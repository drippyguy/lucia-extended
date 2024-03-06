"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const index_js_1 = require("./index.js");
const hmac_js_1 = require("../crypto/hmac.js");
const ecdsa_js_1 = require("../crypto/ecdsa.js");
const rsa_js_1 = require("../crypto/rsa.js");
const index_js_2 = require("../index.js");
vitest_1.test.each(["ES256", "ES384", "ES512"])("Create and validate JWT with %s", async (algorithm) => {
    const { publicKey, privateKey } = await new ecdsa_js_1.ECDSA(ecdsaDictionary[algorithm].hash, ecdsaDictionary[algorithm].curve).generateKeyPair();
    const jwt = await (0, index_js_1.createJWT)(algorithm, privateKey, {
        message: "hello"
    });
    const validatedJWT = await (0, index_js_1.validateJWT)(algorithm, publicKey, jwt);
    (0, vitest_1.expect)(validatedJWT.algorithm).toBe(algorithm);
    (0, vitest_1.expect)(validatedJWT.header).toStrictEqual({
        typ: "JWT",
        alg: algorithm
    });
    (0, vitest_1.expect)(validatedJWT.payload).toStrictEqual({
        message: "hello"
    });
});
vitest_1.test.each(["RS256", "RS384", "RS512"])("Create and validate JWT with %s", async (algorithm) => {
    const { publicKey, privateKey } = await new rsa_js_1.RSASSAPKCS1v1_5(rsassapkcs1v1_5Dictionary[algorithm]).generateKeyPair();
    const jwt = await (0, index_js_1.createJWT)(algorithm, privateKey, {
        message: "hello"
    });
    const validatedJWT = await (0, index_js_1.validateJWT)(algorithm, publicKey, jwt);
    (0, vitest_1.expect)(validatedJWT.algorithm).toBe(algorithm);
    (0, vitest_1.expect)(validatedJWT.header).toStrictEqual({
        typ: "JWT",
        alg: algorithm
    });
    (0, vitest_1.expect)(validatedJWT.payload).toStrictEqual({
        message: "hello"
    });
});
vitest_1.test.each(["PS256", "PS384", "PS512"])("Create and validate JWT with %s", async (algorithm) => {
    const { publicKey, privateKey } = await new rsa_js_1.RSASSAPSS(rsassapssDictionary[algorithm]).generateKeyPair();
    const jwt = await (0, index_js_1.createJWT)(algorithm, privateKey, {
        message: "hello"
    });
    const validatedJWT = await (0, index_js_1.validateJWT)(algorithm, publicKey, jwt);
    (0, vitest_1.expect)(validatedJWT.algorithm).toBe(algorithm);
    (0, vitest_1.expect)(validatedJWT.header).toStrictEqual({
        typ: "JWT",
        alg: algorithm
    });
    (0, vitest_1.expect)(validatedJWT.payload).toStrictEqual({
        message: "hello"
    });
});
vitest_1.test.each(["HS256", "HS384", "HS512"])("Create and validate JWT with %s", async (algorithm) => {
    const secretKey = await new hmac_js_1.HMAC(hmacDictionary[algorithm]).generateKey();
    const jwt = await (0, index_js_1.createJWT)(algorithm, secretKey, {
        message: "hello"
    });
    const validatedJWT = await (0, index_js_1.validateJWT)(algorithm, secretKey, jwt);
    (0, vitest_1.expect)(validatedJWT.algorithm).toBe(algorithm);
    (0, vitest_1.expect)(validatedJWT.header).toStrictEqual({
        typ: "JWT",
        alg: algorithm
    });
    (0, vitest_1.expect)(validatedJWT.payload).toStrictEqual({
        message: "hello"
    });
});
(0, vitest_1.describe)("createJWT()", () => {
    (0, vitest_1.test)("Creates the correct JWT value", async () => {
        const secretKey = new Uint8Array([
            8, 138, 53, 76, 210, 41, 194, 216, 13, 70, 56, 196, 237, 57, 69, 41, 152, 114, 223, 150, 169,
            154, 191, 89, 202, 118, 249, 18, 34, 208, 18, 101, 70, 236, 76, 178, 117, 129, 106, 71, 253,
            79, 99, 9, 64, 208, 102, 50, 118, 72, 107, 46, 120, 2, 240, 217, 103, 66, 63, 52, 248, 23,
            140, 46
        ]);
        const result = await (0, index_js_1.createJWT)("HS256", secretKey, {
            message: "hello",
            count: 100
        }, {
            audiences: ["_audience"],
            issuer: "_issuer",
            subject: "_subject",
            jwtId: "_jwtId"
        });
        const expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXNzYWdlIjoiaGVsbG8iLCJjb3VudCI6MTAwLCJhdWQiOlsiX2F1ZGllbmNlIl0sInN1YiI6Il9zdWJqZWN0IiwiaXNzIjoiX2lzc3VlciIsImp0aSI6Il9qd3RJZCJ9.cKi5L4ZV79IHtpC-rXRwjnQIeWdswAvv1KavDSM_vds";
        (0, vitest_1.expect)(result).toBe(expected);
    });
});
(0, vitest_1.test)("parseJWT()", async () => {
    const secretKey = await new hmac_js_1.HMAC("SHA-256").generateKey();
    const currDateSeconds = Math.floor(Date.now() / 1000);
    const jwt = await (0, index_js_1.createJWT)("HS256", secretKey, {
        message: "hello"
    }, {
        audiences: ["_audience"],
        issuer: "_issuer",
        subject: "_subject",
        jwtId: "_jwtId",
        expiresIn: new index_js_2.TimeSpan(1, "h"),
        notBefore: new Date(),
        includeIssuedTimestamp: true,
        headers: {
            kid: "_kid"
        }
    });
    (0, vitest_1.expect)((0, index_js_1.parseJWT)(jwt)).toEqual({
        algorithm: "HS256",
        expiresAt: new Date((currDateSeconds + new index_js_2.TimeSpan(1, "h").seconds()) * 1000),
        notBefore: new Date(currDateSeconds * 1000),
        issuedAt: new Date(currDateSeconds * 1000),
        audiences: ["_audience"],
        issuer: "_issuer",
        subject: "_subject",
        jwtId: "_jwtId",
        value: jwt,
        parts: jwt.split("."),
        header: {
            kid: "_kid",
            typ: "JWT",
            alg: "HS256"
        },
        payload: {
            message: "hello",
            aud: ["_audience"],
            iss: "_issuer",
            sub: "_subject",
            jti: "_jwtId",
            exp: currDateSeconds + new index_js_2.TimeSpan(1, "h").seconds(),
            iat: currDateSeconds,
            nbf: currDateSeconds
        }
    });
});
(0, vitest_1.describe)("validateJWT", () => {
    (0, vitest_1.test)("Checks expiration", async () => {
        const secretKey = await new hmac_js_1.HMAC("SHA-256").generateKey();
        const jwt1 = await (0, index_js_1.createJWT)("HS256", secretKey, {}, {
            expiresIn: new index_js_2.TimeSpan(-1, "s")
        });
        const jwt2 = await (0, index_js_1.createJWT)("HS256", secretKey, {}, {
            expiresIn: new index_js_2.TimeSpan(0, "s")
        });
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS256", secretKey, jwt1)).rejects.toThrowError();
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS256", secretKey, jwt2)).rejects.toThrowError();
    });
    (0, vitest_1.test)("Checks not before time", async () => {
        const secretKey = await new hmac_js_1.HMAC("SHA-256").generateKey();
        const jwt1 = await (0, index_js_1.createJWT)("HS256", secretKey, {}, {
            notBefore: new Date(Date.now() + 1000)
        });
        const jwt2 = await (0, index_js_1.createJWT)("HS256", secretKey, {}, {
            notBefore: new Date()
        });
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS256", secretKey, jwt1)).rejects.toThrowError();
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS256", secretKey, jwt2)).resolves.not.toThrowError();
    });
    (0, vitest_1.test)("Throws on invalid algorithm", async () => {
        const secretKey = await new hmac_js_1.HMAC("SHA-256").generateKey();
        const jwt = await (0, index_js_1.createJWT)("HS256", secretKey, {}, {
            notBefore: new Date(Date.now() + 1000)
        });
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS512", secretKey, jwt)).rejects.toThrowError();
    });
    (0, vitest_1.test)("Throws on invalid signature", async () => {
        const secretKey = await new hmac_js_1.HMAC("SHA-256").generateKey();
        const jwt = await (0, index_js_1.createJWT)("HS256", secretKey, {}, {
            notBefore: new Date(Date.now() + 1000)
        });
        const invalidKey = await new hmac_js_1.HMAC("SHA-256").generateKey();
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS512", invalidKey, jwt)).rejects.toThrowError();
    });
    (0, vitest_1.test)("Throws on invalid JWT", async () => {
        const secretKey = await new hmac_js_1.HMAC("SHA-256").generateKey();
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS256", secretKey, "huhuihdeuihdiheud")).rejects.toThrowError();
        await (0, vitest_1.expect)((0, index_js_1.validateJWT)("HS256", secretKey, "huhuihdeuihdiheudheiuhdehd.dededed.deded")).rejects.toThrowError();
    });
});
const ecdsaDictionary = {
    ES256: {
        hash: "SHA-256",
        curve: "P-256"
    },
    ES384: {
        hash: "SHA-384",
        curve: "P-384"
    },
    ES512: {
        hash: "SHA-512",
        curve: "P-521"
    }
};
const hmacDictionary = {
    HS256: "SHA-256",
    HS384: "SHA-384",
    HS512: "SHA-512"
};
const rsassapkcs1v1_5Dictionary = {
    RS256: "SHA-256",
    RS384: "SHA-384",
    RS512: "SHA-512"
};
const rsassapssDictionary = {
    PS256: "SHA-256",
    PS384: "SHA-384",
    PS512: "SHA-512"
};
