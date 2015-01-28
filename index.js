"use strict";

module.exports = function (options) {

  let ignoredRoutes = (options.ignoredRoutes && Array.isArray(options.ignoredRoutes)) ? options.ignoredRoutes : [];

  // username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
  function connectionString(dbConfig) {
    let hostPortPairs = dbConfig.uris.map(function (uri) {
      return `${uri}/${dbConfig.options.database}`;
    }).join(",");
    if (dbConfig.options.username.length > 0) {
      return `${dbConfig.options.username}:${dbConfig.options.password}@${hostPortPairs}`;
    }
    return hostPortPairs;
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

  function shouldIgnoreRoute(originalUrl) {
    return ignoredRoutes.some(function (regExp) {
      return originalUrl.match(regExp) || null;
    });
  }

  function innerAuthenticateMiddleware(req, res, next) {
    if (shouldIgnoreRoute(req.originalUrl) > 0) {
      next();
    } else {
      passport.authenticate("localapikey", {session: false})(req, res, next);
    }
  }

  passport.use(new LocalStrategy({apiKeyHeader: "x-api-key"},
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
