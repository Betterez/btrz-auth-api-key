"use strict";

const constants = require("./constants");

function normalizeChannel(channel) {
  return channel.trim().toLowerCase();
}

function getRequestChannels(req) {
  const channel = (req.body ? req.body.channel : "") || (req.query ? req.query.channel : "") || "";
  let channels = (req.body ? req.body.channels : "") || (req.query ? req.query.channels : "") || "";
  const result = [];

  if (channel) {
    result.push({source: "channel", value: normalizeChannel(channel)});
  }

  if (channels) {
    if (!Array.isArray(channels)) {
      channels = channels.split(",");
    }

    channels.forEach(function (ch) {
      if (ch && ch.trim()) {
        result.push({source: "channels", value: normalizeChannel(ch)});
      }
    });
  }

  return result;
}

function getAgencyContext(req) {
  if (!req.account || !req.account.accountId) {
    return {
      isAgency: false,
      agencyId: null,
      providerId: null,
      providerIds: []
    };
  }

  const accountId = req.account.accountId;
  const providerId = (req.body ? req.body.providerId : "") || (req.query ? req.query.providerId : "") || "";
  let providerIdsRaw = (req.body ? req.body.providerIds : "") || (req.query ? req.query.providerIds : "") || "";

  if (!providerId && !providerIdsRaw) {
    return {
      isAgency: false,
      agencyId: null,
      providerId: accountId,
      providerIds: [accountId]
    };
  }

  if (providerId) {
    const isAgency = providerId !== accountId;

    return {
      isAgency: isAgency,
      agencyId: isAgency ? accountId : null,
      providerId: providerId,
      providerIds: [providerId]
    };
  }

  const providerIds = Array.isArray(providerIdsRaw) ?
    providerIdsRaw.map(function (id) { return id.trim(); }) :
    providerIdsRaw.split(",").map(function (id) { return id.trim(); }).filter(Boolean);
  const isAgency = !(providerIds.length === 1 && providerIds[0] === accountId);

  return {
    isAgency: isAgency,
    agencyId: isAgency ? accountId : null,
    providerId: providerIds.length === 1 ? providerIds[0] : null,
    providerIds: providerIds
  };
}

function isAgencyChannel(channel) {
  return constants.AGENCY_CHANNELS.indexOf(channel) > -1;
}

function validateAgencyChannelUsage(req) {
  const agencyContext = getAgencyContext(req);
  const requestChannels = getRequestChannels(req);

  if (!agencyContext.isAgency || requestChannels.length === 0) {
    return {invalid: false};
  }

  const invalidChannels = requestChannels.filter(function (ch) {
    return !isAgencyChannel(ch.value);
  });

  if (invalidChannels.length === 0) {
    return {invalid: false};
  }

  return {
    invalid: true,
    logContext: {
      message: "Agency request is using a non-agency channel",
      accountId: req.account.accountId,
      providerIds: agencyContext.providerIds,
      invalidChannels: invalidChannels.map(function (ch) { return ch.value; }),
      method: req.method,
      url: req.originalUrl || req.url
    }
  };
}

function createLogAgencyChannelMisuseMiddleware(logger) {
  return function logAgencyChannelMisuse(req, res, next) {
    const validationResult = validateAgencyChannelUsage(req);

    if (validationResult.invalid) {
      logger.error("AGENCY_WRONG_CHANNEL: Agency request is using a non-agency channel", validationResult.logContext);
    }

    return next();
  };
}

module.exports = {
  getAgencyContext,
  getRequestChannels,
  isAgencyChannel,
  validateAgencyChannelUsage,
  createLogAgencyChannelMisuseMiddleware
};
