"use strict";

module.exports = function (options) {

  let ignoredRoutes = options.ignoredRoutes && Array.isArray(options.ignoredRoutes) ? options.ignoredRoutes : [];
  let strategyOptions = {
    apiKeyHeader: options.authKeyFields && options.authKeyFields.header ? options.authKeyFields.header : "x-api-key",
    apiKeyField: options.authKeyFields && options.authKeyFields.request ? options.authKeyFields.request : "x-api-key"
  };

  // username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]

  let passport = require("passport"),
    LocalStrategy = require("passport-localapikey-update").Strategy,
    SimpleDao = require("btrz-simple-dao").SimpleDao,
    simpleDao = new SimpleDao(options),
    jwt = require("jsonwebtoken");

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

  function useTestToken(token) {
    if (isTestToken(token)) {
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

  function isTestToken (token) {
    return (token === options.testToken);
  }

  function useDb(apikey) {
    let query = {};
    query[options.collection.property] =  apikey;
    return simpleDao.connect()
      .then((db) => {
        return db.collection(options.collection.name).findOne(query);
      })
      .catch((err) => {
        return Promise.reject(err);
      });
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
      let onSuccess = function (result) { return done(null, result); },
        onErr = function (err) { return done(err, null); };

      let result = findByApiKey(apikey).then(onSuccess, onErr);
      if (result.done) {
        result.done();
      }
    }
  ));

  function getToken (req) {
    return req.headers.authorization.replace(/^Bearer /, "");
  }

  function authenticateTokenMiddleware (req, res, next) {
    if (!req.account || !req.account.privateKey || !req.headers.authorization) {
      return res.status(401).send("Unauthorized");
    }
    let token = getToken(req);
    let tokenVerifyOptions = {
        algorithms: ["HS512"],
        subject: "account_user_sign_in",
        issuer: "btrz-api-accounts",
    };
    try {
      let tokenPayload = useTestToken(token) || jwt.verify(token, req.account.privateKey, tokenVerifyOptions);
      req.user = tokenPayload;
      next();
    } catch (err) {
      if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
        return res.status(401).send("Unauthorized");
      }
      return next(err);
    }
  }

  //if channel 'backoffice' is requested in the body or querystring,
  //checks request has a valid token for backoffice ('betterez-app' internal application)
  function tokenSecuredForBackoffice (req, res, next) {
    let channel = (req.body ? req.body.channel : "") || (req.query ? req.query.channel : "");
    if (channel === "backoffice") {
      authenticateTokenMiddleware(req, res, function (err) {
        if (err) {
          return next(err);
        }
        if (isTestToken(getToken(req))) {
          return next();
        }
        if (!req.user || req.user.aud !== "betterez-app") {
          return res.status(401).send("Unauthorized");
        } else {
          return next();
        }
      });
    } else {
      return next();
    }
  }

  return {
    initialize: function (passportInitOptions) {
      return passport.initialize(passportInitOptions);
    },
    authenticate: function () {
      return innerAuthenticateMiddleware;
    },
    tokenSecured: authenticateTokenMiddleware,
    tokenSecuredForBackoffice: tokenSecuredForBackoffice
  };
};
