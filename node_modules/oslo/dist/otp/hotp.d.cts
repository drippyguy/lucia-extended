import type { TypedArray } from "../index.cjs";
export declare function generateHOTP(key: ArrayBuffer | TypedArray, counter: number, digits?: number): Promise<string>;
