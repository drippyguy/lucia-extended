import type { PasswordHashingAlgorithm } from "./index.cjs";
import type { TypedArray } from "../index.cjs";
export declare class Argon2id implements PasswordHashingAlgorithm {
    constructor(options?: {
        memorySize?: number;
        iterations?: number;
        tagLength?: number;
        parallelism?: number;
        secret?: ArrayBuffer | TypedArray;
    });
    private memorySize?;
    private iterations?;
    private tagLength?;
    private parallelism?;
    private secret;
    hash(password: string): Promise<string>;
    verify(hash: string, password: string): Promise<boolean>;
}
