"use strict";

module.exports = function (options) {

  let ignoredRoutes = options.ignoredRoutes && Array.isArray(options.ignoredRoutes) ? options.ignoredRoutes : [];
  let strategyOptions = {
    apiKeyHeader: options.authKeyFields && options.authKeyFields.header ? options.authKeyFields.header : "x-api-key",
    apiKeyField: options.authKeyFields && options.authKeyFields.request ? options.authKeyFields.request : "x-api-key"
  };

  // username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
  function connectionString(dbConfig) {
    let hostPortPairs = dbConfig.uris.map(function (uri) {
      return `${uri}`;
    }).join(",");
    if (dbConfig.options.username.length > 0) {
      return `${dbConfig.options.username}:${dbConfig.options.password}@${hostPortPairs}/${dbConfig.options.database}`;
    }
    return `${hostPortPairs}/${dbConfig.options.database}`;
  }

  let _ = require("lodash"),
    passport = require("passport"),
    LocalStrategy = require("passport-localapikey-update").Strategy,
    pmongo = require("promised-mongo"),
    db = pmongo(connectionString(options.db));

  function useTestKey(apikey) {
    if (apikey === options.testKey) {
      return new Promise(function (resolve) {
        if (options.testUser) {
          resolve(options.testUser);
        } else {
          resolve(true);
        }
      });
    }
    return null;
  }

  function useDb(apikey) {
    let query = {};
    query[options.collection.property] =  apikey;
    return db.collection(options.collection.name).findOne(query);
  }

  function findByApiKey(apikey) {
    return useTestKey(apikey) || useDb(apikey);
  }

  function shouldIgnoreRoute(originalUrl, method) {
    return ignoredRoutes.some(function (ignoredRoute) {
      if (typeof ignoredRoute === "string") {
        return originalUrl.match(ignoredRoute) || null;
      } else if (typeof ignoredRoute === "object") {
        let methodMatches = (ignoredRoute.methods.indexOf(method) > -1);
        return (methodMatches && originalUrl.match(ignoredRoute.route));
      } else {
        return null;
      }
    });
  }

  function innerAuthenticateMiddleware(req, res, next) {
    if (shouldIgnoreRoute(req.originalUrl, req.method)) {
      next();
    } else {
      passport.authenticate("localapikey", {session: false})(req, res, next);
    }
  }

  passport.use(new LocalStrategy(strategyOptions,
    function (apikey, done) {
      let onSuccess = _.partial(done, null),
        onErr = _.partialRight(done, null);
      let result = findByApiKey(apikey).then(onSuccess, onErr);
      if (result.done) {
        result.done();
      }
    }
  ));

  return {
    initialize: function (passportInitOptions) {
      return passport.initialize(passportInitOptions);
    },
    authenticate: function () {
      return innerAuthenticateMiddleware;
    }
  };
};
