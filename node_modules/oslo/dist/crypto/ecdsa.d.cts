import type { TypedArray } from "../index.cjs";
import type { KeyPair } from "./index.cjs";
import type { SHAHash } from "./sha.cjs";
export type ECDSACurve = "P-256" | "P-384" | "P-521";
export declare class ECDSA {
    private hash;
    private curve;
    constructor(hash: SHAHash, curve: ECDSACurve);
    sign(privateKey: ArrayBuffer | TypedArray, data: ArrayBuffer | TypedArray): Promise<ArrayBuffer>;
    verify(publicKey: ArrayBuffer | TypedArray, signature: ArrayBuffer | TypedArray, data: ArrayBuffer | TypedArray): Promise<boolean>;
    generateKeyPair(): Promise<KeyPair>;
}
