"use strict";

const {describe, it, mock} = require("node:test");
const assert = require("node:assert/strict");
const {
  getAgencyContext,
  getRequestChannels,
  isAgencyChannel,
  validateAgencyChannelUsage,
  createLogAgencyChannelMisuseMiddleware
} = require("../agencyChannelValidation");

describe("agencyChannelValidation", function () {
  const agencyAccountId = "595f9c7007ee12686d000032";
  const providerAccountId = "507f1f77bcf86cd799439011";

  function buildReq(overrides) {
    return Object.assign({
      method: "GET",
      originalUrl: "/inventory/fares",
      account: {accountId: agencyAccountId, name: "agency-app"},
      application: {_id: "608808b2481ef95330d4b98e", name: "agency-app", accountId: agencyAccountId},
      query: {},
      body: {}
    }, overrides);
  }

  describe("getAgencyContext", function () {
    it("should not detect agency when providerId is missing", function () {
      const context = getAgencyContext(buildReq());

      assert.equal(context.isAgency, false);
      assert.equal(context.agencyId, null);
      assert.deepEqual(context.providerIds, [agencyAccountId]);
    });

    it("should not detect agency when providerId matches the api key account", function () {
      const context = getAgencyContext(buildReq({query: {providerId: agencyAccountId}}));

      assert.equal(context.isAgency, false);
      assert.equal(context.agencyId, null);
      assert.equal(context.providerId, agencyAccountId);
    });

    it("should detect agency when providerId is a different account", function () {
      const context = getAgencyContext(buildReq({query: {providerId: providerAccountId}}));

      assert.equal(context.isAgency, true);
      assert.equal(context.agencyId, agencyAccountId);
      assert.equal(context.providerId, providerAccountId);
    });

    it("should detect agency when providerIds contains another account", function () {
      const context = getAgencyContext(buildReq({query: {providerIds: providerAccountId}}));

      assert.equal(context.isAgency, true);
      assert.equal(context.agencyId, agencyAccountId);
      assert.deepEqual(context.providerIds, [providerAccountId]);
    });

    it("should not detect agency when providerIds only contains the api key account", function () {
      const context = getAgencyContext(buildReq({query: {providerIds: agencyAccountId}}));

      assert.equal(context.isAgency, false);
      assert.equal(context.agencyId, null);
    });

    it("should read providerId from the request body", function () {
      const context = getAgencyContext(buildReq({body: {providerId: providerAccountId}}));

      assert.equal(context.isAgency, true);
      assert.equal(context.providerId, providerAccountId);
    });
  });

  describe("getRequestChannels", function () {
    it("should read channel from querystring", function () {
      const channels = getRequestChannels(buildReq({query: {channel: "Backoffice"}}));

      assert.deepEqual(channels, [{source: "channel", value: "backoffice"}]);
    });

    it("should read channels from body", function () {
      const channels = getRequestChannels(buildReq({body: {channels: ["websales", "agency-websales"]}}));

      assert.deepEqual(channels, [
        {source: "channels", value: "websales"},
        {source: "channels", value: "agency-websales"}
      ]);
    });

    it("should split comma-separated channels from querystring", function () {
      const channels = getRequestChannels(buildReq({query: {channels: "backoffice,agency-backoffice"}}));

      assert.deepEqual(channels, [
        {source: "channels", value: "backoffice"},
        {source: "channels", value: "agency-backoffice"}
      ]);
    });
  });

  describe("isAgencyChannel", function () {
    it("should accept agency channels only", function () {
      assert.equal(isAgencyChannel("agency-backoffice"), true);
      assert.equal(isAgencyChannel("agency-websales"), true);
      assert.equal(isAgencyChannel("backoffice"), false);
      assert.equal(isAgencyChannel("websales"), false);
    });
  });

  describe("validateAgencyChannelUsage", function () {
    it("should ignore non-agency requests", function () {
      const result = validateAgencyChannelUsage(buildReq({query: {channel: "backoffice"}}));

      assert.equal(result.invalid, false);
    });

    it("should ignore agency requests without channel information", function () {
      const result = validateAgencyChannelUsage(buildReq({query: {providerId: providerAccountId}}));

      assert.equal(result.invalid, false);
    });

    it("should accept agency requests using agency channels", function () {
      const result = validateAgencyChannelUsage(buildReq({
        query: {
          providerId: providerAccountId,
          channel: "agency-backoffice"
        }
      }));

      assert.equal(result.invalid, false);
    });

    it("should flag agency requests using non-agency channels", function () {
      const result = validateAgencyChannelUsage(buildReq({
        method: "POST",
        originalUrl: "/sales/cart",
        body: {
          providerId: providerAccountId,
          channel: "backoffice"
        }
      }));

      assert.equal(result.invalid, true);
      assert.equal(result.logContext.accountId, agencyAccountId);
      assert.deepEqual(result.logContext.providerIds, [providerAccountId]);
      assert.deepEqual(result.logContext.invalidChannels, ["backoffice"]);
      assert.equal(result.logContext.method, "POST");
      assert.equal(result.logContext.url, "/sales/cart");
    });

    it("should flag invalid channels when channels is provided", function () {
      const result = validateAgencyChannelUsage(buildReq({
        query: {
          providerIds: `${providerAccountId},${agencyAccountId}`,
          channels: "websales,agency-websales"
        }
      }));

      assert.equal(result.invalid, true);
      assert.deepEqual(result.logContext.invalidChannels, ["websales"]);
    });
  });

  describe("createLogAgencyChannelMisuseMiddleware", function () {
    it("should log an error and continue the request", function () {
      const logger = {error: mock.fn()};
      const middleware = createLogAgencyChannelMisuseMiddleware(logger);
      const req = buildReq({
        query: {
          providerId: providerAccountId,
          channel: "websales"
        }
      });
      const next = mock.fn();

      middleware(req, {}, next);

      assert.strictEqual(logger.error.mock.callCount(), 1);
      assert.strictEqual(logger.error.mock.calls[0].arguments[0], "AGENCY_WRONG_CHANNEL: Agency request is using a non-agency channel");
      assert.deepStrictEqual(logger.error.mock.calls[0].arguments[1].accountId, agencyAccountId);
      assert.deepStrictEqual(logger.error.mock.calls[0].arguments[1].providerIds, [providerAccountId]);
      assert.deepStrictEqual(logger.error.mock.calls[0].arguments[1].invalidChannels, ["websales"]);
      assert.strictEqual(next.mock.callCount(), 1);
    });

    it("should not log when the agency channel is valid", function () {
      const logger = {error: mock.fn()};
      const middleware = createLogAgencyChannelMisuseMiddleware(logger);
      const next = mock.fn();

      middleware(buildReq({
        query: {
          providerId: providerAccountId,
          channel: "agency-websales"
        }
      }), {}, next);

      assert.strictEqual(logger.error.mock.callCount(), 0);
      assert.strictEqual(next.mock.callCount(), 1);
    });
  });
});
