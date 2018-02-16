"use strict";

const assert = require("assert"),
  jwt = require("jsonwebtoken"),
  constants = require("./constants");


class InternalAuthTokenProvider {

  constructor({internalAuthTokenSigningSecrets} = {}) {
    assert(internalAuthTokenSigningSecrets.main, "you must provide a main signing key");

    this._signingSecret = internalAuthTokenSigningSecrets.main;
    this._tokenGenerationTimestamp = 0;
    this._token = null;
  }

  /**
   * Gets a token that's suitable for making internal service-to-service API calls.
   * @returns {String} the token
   */
  getToken() {
    const tokenRefreshIntervalMs = 60000, // One minute
      currentTimestamp = new Date().getTime(),
      msSinceTokenGeneration = currentTimestamp - this._tokenGenerationTimestamp;

    if (msSinceTokenGeneration >= tokenRefreshIntervalMs) {
      const jwtOptions = {
          algorithm: "HS512",
          expiresIn: "2 minutes",
          issuer: constants.INTERNAL_AUTH_TOKEN_ISSUER,
          audience: "betterez-app",
        },
        payload = {};

      this._token = jwt.sign(payload, this._signingSecret, jwtOptions);
      this._tokenGenerationTimestamp = currentTimestamp;
    }

    return this._token;
  }
}

module.exports = InternalAuthTokenProvider;
