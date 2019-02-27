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

  function isTestToken(token) {
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
        .then((result) => {
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
        const token = result && result.key;
        const jwtToken = getAuthToken(req);
        req.application = result;
        req.tokens = { token, jwtToken };
        // done executes Passport login and fills req.user (or it's alias if userProperty is defined in root index.js)
        done(null, result);

        if (jwtToken) {
          tokenProcess(req, jwtToken);
        }
      };
      let onErr = function (err) { return done(err, null); };

      let result = findByApiKey(apikey).then(onSuccess, onErr);
      if (result.done) {
        result.done();
      }
    }
  ));

  function getAuthToken(req) {
    const authorizationHeader = req.headers.authorization || "";
    const jwtTokenRegExp = /Bearer (.*)/i;
    const authHeaderIsValid = jwtTokenRegExp.test(authorizationHeader);
    const jwtToken = authHeaderIsValid ? authorizationHeader.match(jwtTokenRegExp)[1] : null;

    return jwtToken;
  }

  function decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch (err) {
      return null;
    }
  }

  function shouldValidateAccount(bypassAccount, req) {
    return !bypassAccount && !(req.account && req.account.privateKey);
  }

  function verifyInternalToken(token, secrets) {

    function verify(keyName, opts) {
      try {
        return jwt.verify(token, secrets[keyName], opts);
      } catch (err) {
        // failing to validate the token against one of the signing keys is expected behaviour when a key rotation is in progress
        logger.info(`authenticateTokenMiddleware: Failed to validate internal auth token using ${keyName} signing key`, err);
        return false;
      }
    }

    const opts = {
      algorithms: ["HS512"],
      issuer: constants.INTERNAL_AUTH_TOKEN_ISSUER,
    };

    return verify("main", opts) || verify("secondary", opts);
  }

  function authenticateTokenMiddleware(req, res, next, options = {}) {
    const {bypassAccount = false} = options;

    if (shouldValidateAccount(bypassAccount, req)) {
      logger.error("authenticateTokenMiddleware: No account or account has no private key");
      return res.status(401).send("Unauthorized");
    } else if (!req.headers.authorization) {
      logger.info("authenticateTokenMiddleware: Request is missing 'authorization' header");
      return res.status(401).send("Unauthorized");
    }

    // at this point headers.authorization was already checked for existency
    const jwtToken = getAuthToken(req);

    // moving a the token process to a unified function
    // which will also be used after the passport login happens
    // but omitting res, next and options
    processJwtToken(req, jwtToken, res, next, options);
  }

  function tokenSecured(req, res, next) {
    return authenticateTokenMiddleware(req, res, next);
  }

  //if channel 'backoffice' or 'agency-backoffice' is requested in the body or querystring,
  //checks request has a valid token for backoffice ('betterez-app' internal application)
  function tokenSecuredForBackoffice(req, res, next) {
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
        if (isTestToken(getAuthToken(req))) {
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

  function customerTokenSecured(req, res, next) {
    return authenticateTokenMiddleware(req, res, next, {audience: "customer"});
  }

  function tokenSecuredWithoutAccount(req, res, next) {
    return authenticateTokenMiddleware(req, res, next, {bypassAccount: true});
  }

  function tokenSecuredForAudiences(audiences) {
    return function (req, res, next) {
      return authenticateTokenMiddleware(req, res, function (err) {
        if (err) {
          return next(err);
        }
        if (isTestToken(getAuthToken(req))) {
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

  function processJwtToken(req, token, res = null, next = null, options = {}) {
    const {audience = null, bypassAccount = false} = options;
    const decodedToken = decodeToken(token);

    if (isTestToken(token)) {
      req.user = getTestUser(token);
      return next ? next() : true;
    }

    if (!decodedToken) {
      logger.error("authenticateTokenMiddleware: Token is malformed");
      return res ? res.status(401).send("Unauthorized") : false;
    } else if (!decodedToken.iss) {
      logger.error("authenticateTokenMiddleware: Token does not specify its issuer");
      return res ? res.status(401).send("Unauthorized") : false;
    }

    const isInternalToken = decodedToken.iss === constants.INTERNAL_AUTH_TOKEN_ISSUER;

    if (isInternalToken) {
      const tokenPayload = verifyInternalToken(token, internalAuthTokenSigningSecrets);

      if (!tokenPayload) {
        logger.error("authenticateTokenMiddleware: Failed to validate internal auth token using any signing key");
        return res ? res.status(401).send("Unauthorized") : false;
      }
      if (bypassAccount) {
        return next ? next() : true;
      }

      return findUserById(req.account.userId)
        .then((user) => {
          // This should not happen: the application record / api key references a userId that does not exist or has been deleted.
          // Modify the source data.
          assert(user, `unable to find user with id ${req.account.userId}`);

          Reflect.deleteProperty(user, "password");
          req.user = Object.assign({}, user, tokenPayload);
          return next ? next() : true;
        })
        .catch((err) => {
          logger.error(`authenticateTokenMiddleware: Error occurred finding user with id ${req.account.userId}`, err);
          return res ? res.status(401).send("Unauthorized") : false;
        });
    } else {
      // Validate a user-provided token
      try {
        const userTokenVerifyOptions = {
          algorithms: ["HS512"],
          subject: "account_user_sign_in",
          issuer: constants.USER_AUTH_TOKEN_ISSUER,
        };

        if (audience) {
          userTokenVerifyOptions.audience = audience;
        }
        req.user = jwt.verify(token, req.account.privateKey, userTokenVerifyOptions);
        return next ? next() : true;
      } catch (err) {
        if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
          logger.info(`authenticateTokenMiddleware: Token expired or 'JsonWebTokenError' occurred`, err);
          return res ? res.status(401).send("Unauthorized") : false;
        }

        logger.error(`authenticateTokenMiddleware: Unexpected error occurred validating user token`, err);
        return res ? res.status(401).send("Unauthorized") : false;
      }
    }
  }

  return {
    initialize: function (passportInitOptions) {
      return passport.initialize(passportInitOptions);
    },
    authenticate: function () {
      return innerAuthenticateMiddleware;
    },
    tokenSecured,
    tokenSecuredWithoutAccount,
    tokenSecuredForBackoffice,
    tokenSecuredForAudiences,
    customerTokenSecured
  };
};

module.exports = {
  Authenticator,
  InternalAuthTokenProvider
};
