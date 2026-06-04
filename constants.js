"use strict";

const constants = {
  INTERNAL_AUTH_TOKEN_SYMBOL: "internal_auth_token",
  INTERNAL_AUTH_TOKEN_ISSUER: "btrz-api-client",
  USER_AUTH_TOKEN_ISSUER: "btrz-api-accounts",
  DB_USER_COLLECTION_NAME: "users",
  CHANNELS: {
    BACKOFFICE: "backoffice",
    AGENCY_BACKOFFICE: "agency-backoffice",
    WEBSALES: "websales",
    AGENCY_WEBSALES: "agency-websales"
  },
  AGENCY_CHANNELS: ["agency-backoffice", "agency-websales"]
};

module.exports = constants;
