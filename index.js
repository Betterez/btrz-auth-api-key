"use strict";

const assert = require("assert"),
  constants = require("./constants"),
  InternalAuthTokenProvider = require("./internalAuthTokenProvider");

function Authenticator(options, logger) {

  assert(logger && logger.info && logger.error, "you must provide a logger");
  assert(options.internalAuthTokenSigningSecrets, "you must provide 'internalAuthTokenSigningSecrets'");
  assert(options.internalAuthTokenSigningSecrets.main, "you must provide 'internalAuthTokenSigningSecrets.main'");
  assert(options.internalAuthTokenSigningSecrets.secondary, "you must provide 'internalAuthTokenSigningSecrets.secondary'");

  const internalAuthTokenSigningSecrets = options.internalAuthTokenSigningSecrets;
  const ignoredRoutes = options.ignoredRoutes && Array.isArray(options.ignoredRoutes) ? options.ignoredRoutes : [];
  const strategyOptions = {
    passReqToCallback: true,
    apiKeyHeader: options.authKeyFields && options.authKeyFields.header ? options.authKeyFields.header : "x-api-key",
    apiKeyField: options.authKeyFields && options.authKeyFields.request ? options.authKeyFields.request : "x-api-key"
  };

  // username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]

  const passport = require("passport"),
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

  function getTestUser(token) {
    if (isTestToken(token)) {
      if (options.testUser) {
        return options.testUser;
      } else {
        return true;
      }
    }
    return null;
  }

  function isTestToken (token) {
    return (token && token === options.testToken);
  }

  function isCorrectBackOfficeAudience(audience) {
    return Array.isArray(options.audiences) ? options.audiences.indexOf(audience) > -1 : audience === "betterez-app";
  }

  function useDb(apikey) {
    let query = {};
    query[options.collection.property] =  apikey;
    return simpleDao.connect()
      .then((db) => {
        return db.collection(options.collection.name).findOne(query)
        .then(result => {
          if(!result) {
            logger.error("api-key not found");
          }
          return result;
        });
      })
      .catch((err) => {
        return Promise.reject(err);
      });
  }

  function findByApiKey(apikey) {
    return useTestKey(apikey) || useDb(apikey);
  }


  function findUserById(userId) {
    if(typeof userId !== "string") {
      return Promise.reject(new Error("userId must be a string"));
    }

    return simpleDao.connect()
      .then((db) => {
        return db.collection(constants.DB_USER_COLLECTION_NAME).findOne({_id: simpleDao.objectId(userId), deleted: false});
      });
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
    function (req, apikey, done) {
      let onSuccess = function (result) {
        req.application = result;
        return done(null, result);
      };
      let onErr = function (err) { return done(err, null); };

      let result = findByApiKey(apikey).then(onSuccess, onErr);
      if (result.done) {
        result.done();
      }
    }
  ));

  function getToken (req) {
    return req.headers.authorization.replace(/^Bearer /, "");
  }

  function authenticateTokenMiddleware (req, res, next, options = {}) {
    const {audience} = options;

    if (!req.account || !req.account.privateKey) {
      logger.error("authenticateTokenMiddleware: No account or account has no private key");
      return res.status(401).send("Unauthorized");
    } else if (!req.headers.authorization) {
      logger.info("authenticateTokenMiddleware: Request is missing 'authorization' header");
      return res.status(401).send("Unauthorized");
    }

    const token = getToken(req),
      decodedToken = jwt.decode(token),
      userTokenVerifyOptions = {
        algorithms: ["HS512"],
        subject: "account_user_sign_in",
        issuer: constants.USER_AUTH_TOKEN_ISSUER,
      },
      internalTokenVerifyOptions = {
        algorithms: ["HS512"],
        issuer: constants.INTERNAL_AUTH_TOKEN_ISSUER,
      };

    let tokenPayload = null;

    if (isTestToken(token)) {
      req.user = getTestUser(token);
      return next();
    }

    if (audience) {
      userTokenVerifyOptions.audience = audience;
    }

    if (!decodedToken) {
      logger.error("authenticateTokenMiddleware: Token is malformed");
      return res.status(401).send("Unauthorized");
    } else if (!decodedToken.iss) {
      logger.error("authenticateTokenMiddleware: Token does not specify its issuer");
      return res.status(401).send("Unauthorized");
    }

    const isInternalToken = decodedToken.iss === constants.INTERNAL_AUTH_TOKEN_ISSUER;

    if (isInternalToken) {
      // Validate a token for service-to-service communication
      let verified = false;

      [internalAuthTokenSigningSecrets.main, internalAuthTokenSigningSecrets.secondary].forEach((secret, index) => {
        if (verified) return;

        try {
          tokenPayload = jwt.verify(token, secret, internalTokenVerifyOptions);
          verified = true;
        } catch (err) {
          // Log and swallow errors
          const signingKeyName = index === 0 ? "main" : "secondary";
          // failing to validate the token against one of the signing keys is expected behaviour when a key rotation is in progress
          logger.info(`authenticateTokenMiddleware: Failed to validate internal auth token using ${signingKeyName} signing key`, err);
        }
      });

      if (!verified) {
        logger.error("authenticateTokenMiddleware: Failed to validate internal auth token using any signing key");
        return res.status(401).send("Unauthorized");
      } else {
        return findUserById(req.account.userId)
          .then((user) => {
            // This should not happen: the application record / api key references a userId that does not exist or has been deleted.
            // Modify the source data.
            assert(user, `unable to find user with id ${req.account.userId}`);

            Reflect.deleteProperty(user, "password");
            req.user = Object.assign({}, user, tokenPayload);
            return next();
          })
          .catch((err) => {
            logger.error(`authenticateTokenMiddleware: Error occurred finding user with id ${req.account.userId}`, err);
            return res.status(401).send("Unauthorized");
          });
      }
    } else {
      // Validate a user-provided token
      try {
        tokenPayload = jwt.verify(token, req.account.privateKey, userTokenVerifyOptions);
        req.user = tokenPayload;
        return next();
      } catch (err) {
        if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
          logger.info(`authenticateTokenMiddleware: Token expired or 'JsonWebTokenError' occurred`, err);
          return res.status(401).send("Unauthorized");
        }

        logger.error(`authenticateTokenMiddleware: Unexpected error occurred validating user token`, err);
        return res.status(401).send("Unauthorized");
      }
    }
  }

  function tokenSecured (req, res, next) {
    return authenticateTokenMiddleware(req, res, next);
  }

  //if channel 'backoffice' or 'agency-backoffice' is requested in the body or querystring,
  //checks request has a valid token for backoffice ('betterez-app' internal application)
  function tokenSecuredForBackoffice (req, res, next) {
    let channel = (req.body ? req.body.channel : "") || (req.query ? req.query.channel : "");
    let channels = (req.body ? req.body.channels : "") || (req.query ? req.query.channels : "");
    let mustAuth = false;

    if (channels) {
      if (!Array.isArray(channels)) {
        channels = channels.split(",");
      }

      channels.forEach(function (ch) {
        if (ch.trim().toLowerCase() === "backoffice" || ch.trim().toLowerCase() === "agency-backoffice") {
          mustAuth = true;
          return;
        }
      });
    }
    if (!mustAuth && channel && (channel.trim().toLowerCase() === "backoffice" || channel.trim().toLowerCase() === "agency-backoffice")) {
      mustAuth = true;
    }

    if (mustAuth) {
      authenticateTokenMiddleware(req, res, function (err) {
        if (err) {
          return next(err);
        }
        if (isTestToken(getToken(req))) {
          return next();
        }
        if (!req.user || !isCorrectBackOfficeAudience(req.user.aud)) {
          return res.status(401).send("Unauthorized");
        } else {
          return next();
        }
      });
    } else {
      return next();
    }
  }

  function customerTokenSecured (req, res, next) {
    return authenticateTokenMiddleware(req, res, next, {audience: "customer"});
  }

  function tokenSecuredForAudiences (audiences) {
    return function (req, res, next) {
      return authenticateTokenMiddleware(req, res, function (err) {
        if (err) {
          return next(err);
        }
        if (isTestToken(getToken(req))) {
          return next();
        }
        const notAuthenticated = !req.user,
          wrongAudience = audiences.indexOf(req.user.aud) === -1;
        if (notAuthenticated || wrongAudience) {
          return res.status(401).send("Unauthorized");
        } else {
          return next();
        }
      });
    };
  }

  return {
    initialize: function (passportInitOptions) {
      return passport.initialize(passportInitOptions);
    },
    authenticate: function () {
      return innerAuthenticateMiddleware;
    },
    tokenSecured: tokenSecured,
    tokenSecuredForBackoffice: tokenSecuredForBackoffice,
    tokenSecuredForAudiences: tokenSecuredForAudiences,
    customerTokenSecured: customerTokenSecured
  };
};

module.exports = {
  Authenticator,
  InternalAuthTokenProvider
};
