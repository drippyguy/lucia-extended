export { Lucia } from "./core.cjs";
export { Scrypt, LegacyScrypt, generateId } from "./crypto.cjs";
export { TimeSpan } from "oslo";
export { Cookie } from "oslo/cookie";
export { verifyRequestOrigin } from "oslo/request";
export type { User, Session, SessionCookieOptions, SessionCookieAttributesOptions } from "./core.cjs";
export type { DatabaseSession, DatabaseUser, Adapter } from "./database.cjs";
export type { PasswordHashingAlgorithm } from "./crypto.cjs";
export type { CookieAttributes } from "oslo/cookie";
import type { Lucia } from "./core.cjs";
export interface Register {
}
export type RegisteredLucia = Register extends {
    Lucia: infer _Lucia;
} ? _Lucia extends Lucia<any, any> ? _Lucia : Lucia : Lucia;
export type RegisteredDatabaseUserAttributes = Register extends {
    DatabaseUserAttributes: infer _DatabaseUserAttributes;
} ? _DatabaseUserAttributes : {};
export type RegisteredDatabaseSessionAttributes = Register extends {
    DatabaseSessionAttributes: infer _DatabaseSessionAttributes;
} ? _DatabaseSessionAttributes : {};
