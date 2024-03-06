"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var core_exports = {};
__export(core_exports, {
  Lucia: () => Lucia
});
module.exports = __toCommonJS(core_exports);
var import_oslo = require("oslo");
var import_crypto = require("./crypto.cjs");
var import_cookie = require("oslo/cookie");
class Lucia {
  adapter;
  sessionExpiresIn;
  sessionCookieController;
  getSessionAttributes;
  getUserAttributes;
  sessionCookieName;
  constructor(adapter, options) {
    this.adapter = adapter;
    this.getUserAttributes = (databaseUserAttributes) => {
      if (options && options.getUserAttributes) {
        return options.getUserAttributes(databaseUserAttributes);
      }
      return {};
    };
    this.getSessionAttributes = (databaseSessionAttributes) => {
      if (options && options.getSessionAttributes) {
        return options.getSessionAttributes(databaseSessionAttributes);
      }
      return {};
    };
    this.sessionExpiresIn = options?.sessionExpiresIn ?? new import_oslo.TimeSpan(30, "d");
    this.sessionCookieName = options?.sessionCookie?.name ?? "auth_session";
    let sessionCookieExpiresIn = this.sessionExpiresIn;
    if (options?.sessionCookie?.expires === false) {
      sessionCookieExpiresIn = new import_oslo.TimeSpan(365 * 2, "d");
    }
    const baseSessionCookieAttributes = {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      ...options?.sessionCookie?.attributes
    };
    this.sessionCookieController = new import_cookie.CookieController(
      this.sessionCookieName,
      baseSessionCookieAttributes,
      {
        expiresIn: sessionCookieExpiresIn
      }
    );
  }
  async getUserSessions(userId) {
    const databaseSessions = await this.adapter.getUserSessions(userId);
    const sessions = [];
    for (const databaseSession of databaseSessions) {
      if (!(0, import_oslo.isWithinExpirationDate)(databaseSession.expiresAt)) {
        continue;
      }
      sessions.push({
        id: databaseSession.id,
        expiresAt: databaseSession.expiresAt,
        userId: databaseSession.userId,
        fresh: false,
        ...this.getSessionAttributes(databaseSession.attributes)
      });
    }
    return sessions;
  }
  async validateSession(sessionId) {
    const [databaseSession, databaseUser] = await this.adapter.getSessionAndUser(sessionId);
    if (!databaseSession) {
      return { session: null, user: null };
    }
    if (!databaseUser) {
      await this.adapter.deleteSession(databaseSession.id);
      return { session: null, user: null };
    }
    if (!(0, import_oslo.isWithinExpirationDate)(databaseSession.expiresAt)) {
      await this.adapter.deleteSession(databaseSession.id);
      return { session: null, user: null };
    }
    const activePeriodExpirationDate = new Date(
      databaseSession.expiresAt.getTime() - this.sessionExpiresIn.milliseconds() / 2
    );
    const session = {
      ...this.getSessionAttributes(databaseSession.attributes),
      id: databaseSession.id,
      userId: databaseSession.userId,
      fresh: false,
      expiresAt: databaseSession.expiresAt
    };
    if (!(0, import_oslo.isWithinExpirationDate)(activePeriodExpirationDate)) {
      session.fresh = true;
      session.expiresAt = (0, import_oslo.createDate)(this.sessionExpiresIn);
      await this.adapter.updateSessionExpiration(databaseSession.id, session.expiresAt);
    }
    const user = {
      ...this.getUserAttributes(databaseUser.attributes),
      id: databaseUser.id
    };
    return { user, session };
  }
  async createSession(userId, attributes, options) {
    const sessionId = options?.sessionId ?? (0, import_crypto.generateId)(40);
    const sessionExpiresAt = (0, import_oslo.createDate)(this.sessionExpiresIn);
    await this.adapter.setSession({
      id: sessionId,
      userId,
      expiresAt: sessionExpiresAt,
      attributes
    });
    const session = {
      id: sessionId,
      userId,
      fresh: true,
      expiresAt: sessionExpiresAt,
      ...this.getSessionAttributes(attributes)
    };
    return session;
  }
  async invalidateSession(sessionId) {
    await this.adapter.deleteSession(sessionId);
  }
  async invalidateUserSessions(userId) {
    await this.adapter.deleteUserSessions(userId);
  }
  async deleteExpiredSessions() {
    await this.adapter.deleteExpiredSessions();
  }
  readSessionCookie(cookieHeader) {
    const sessionId = this.sessionCookieController.parse(cookieHeader);
    return sessionId;
  }
  readBearerToken(authorizationHeader) {
    const [authScheme, token] = authorizationHeader.split(" ");
    if (authScheme !== "Bearer") {
      return null;
    }
    return token ?? null;
  }
  createSessionCookie(sessionId) {
    return this.sessionCookieController.createCookie(sessionId);
  }
  createBlankSessionCookie() {
    return this.sessionCookieController.createBlankCookie();
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Lucia
});
//# sourceMappingURL=core.cjs.map