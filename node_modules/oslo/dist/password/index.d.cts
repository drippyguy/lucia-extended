export interface PasswordHashingAlgorithm {
    hash(password: string): Promise<string>;
    verify(hash: string, password: string): Promise<boolean>;
}
export { Argon2id } from "./argon2id.cjs";
export { Scrypt } from "./scrypt.cjs";
export { Bcrypt } from "./bcrypt.cjs";
