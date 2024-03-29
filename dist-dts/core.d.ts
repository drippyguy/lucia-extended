import { TimeSpan } from "oslo";
import type { Cookie } from "oslo/cookie";
import type { Adapter } from "./database.js";
import type { RegisteredDatabaseSessionAttributes, RegisteredDatabaseUserAttributes, RegisteredLucia } from "./index.js";
type SessionAttributes = RegisteredLucia extends Lucia<infer _SessionAttributes, any> ? _SessionAttributes : {};
type UserAttributes = RegisteredLucia extends Lucia<any, infer _UserAttributes> ? _UserAttributes : {};
export interface Session extends SessionAttributes {
    id: string;
    expiresAt: Date;
    fresh: boolean;
    userId: string;
}
export interface User extends UserAttributes {
    id: string;
}
export declare class Lucia<_SessionAttributes extends {} = Record<never, never>, _UserAttributes extends {} = Record<never, never>> {
    private adapter;
    private sessionExpiresIn;
    private sessionCookieController;
    private getSessionAttributes;
    private getUserAttributes;
    readonly sessionCookieName: string;
    constructor(adapter: Adapter, options?: {
        sessionExpiresIn?: TimeSpan;
        sessionCookie?: SessionCookieOptions;
        getSessionAttributes?: (databaseSessionAttributes: RegisteredDatabaseSessionAttributes) => _SessionAttributes;
        getUserAttributes?: (databaseUserAttributes: RegisteredDatabaseUserAttributes) => _UserAttributes;
    });
    getUserSessions(userId: string): Promise<Session[]>;
    validateSession(sessionId: string): Promise<{
        user: User;
        session: Session;
    } | {
        user: null;
        session: null;
    }>;
    createSession(userId: string, attributes: RegisteredDatabaseSessionAttributes, options?: {
        sessionId?: string;
    }): Promise<Session>;
    invalidateSession(sessionId: string): Promise<void>;
    invalidateUserSessions(userId: string): Promise<void>;
    deleteExpiredSessions(): Promise<void>;
    readSessionCookie(cookieHeader: string): string | null;
    readBearerToken(authorizationHeader: string): string | null;
    createSessionCookie(sessionId: string): Cookie;
    createBlankSessionCookie(): Cookie;
}
export interface SessionCookieOptions {
    name?: string;
    expires?: boolean;
    attributes?: SessionCookieAttributesOptions;
}
export interface SessionCookieAttributesOptions {
    sameSite?: "lax" | "strict";
    domain?: string;
    path?: string;
    secure?: boolean;
}
export {};
