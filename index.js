"use strict";

const assert = require("assert");
const constants = require("./constants");
const InternalAuthTokenProvider = require("./internalAuthTokenProvider");
const axios = require("axios");

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
  let preLoadedUser = null;

  // username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]

  const passport = require("passport");
  const LocalStrategy = require("passport-localapikey-update").Strategy;
  const SimpleDao = require("btrz-simple-dao").SimpleDao;
  const simpleDao = new SimpleDao(options);
  const jwt = require("jsonwebtoken");

  function useTestKey() {
    return new Promise(function (resolve) {
      if (options.testUser) {
        resolve(options.testUser);
      } else {
        resolve(true);
      }
    });
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

  function getAuthInfo(apikey) {
    const url = `${options.apiUrl}/${apikey}`;
    const payload = {
      headers: {
        "Authorization": `Bearer ${options.internalAuthTokenProvider.getToken()}`
      },
      body: {},
      json: true
    };    
    return axios.get(url, payload)
      .then((info) => {
        preLoadedUser = info.data.user;
        return info.data.application;
      })
      .catch((err) => {
        logger.error("ERROR getting auth info::getAuthInfo::", err);
        return null;
      });
  }

  function useApiAuth() {
    return options.apiAuth && options.apiUrl && options.internalAuthTokenProvider; 
  }

  function findByApiKey(apikey) {
    if (apikey === options.testKey) { 
      return useTestKey(apikey);
    }

    if (useApiAuth()) {
      return getAuthInfo(apikey);
    }

    return useDb(apikey);
  }

  function findUserById(userId) {    
    if (preLoadedUser) {
      return Promise.resolve(preLoadedUser);
    }

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

  function isIgnoredRouteWithoutAuthAttempt(req, strategyOptions) {
    const isXApiKey = req.headers[strategyOptions.apiKeyHeader] || req.query[strategyOptions.apiKeyField]; 
    
    return shouldIgnoreRoute(req.originalUrl, req.method) && !isXApiKey;
  }

  function innerAuthenticateMiddleware(req, res, next) {
    const jwtToken = getAuthToken(req);
    const decodedToken = decodeToken(jwtToken);
    const isXApiKey = req.headers[strategyOptions.apiKeyHeader] || req.query[strategyOptions.apiKeyField]; 
    const someAuthAttempt = decodedToken || isXApiKey;    
    const isInternalToken = decodedToken && decodedToken.iss === constants.INTERNAL_AUTH_TOKEN_ISSUER;

    if(isInternalToken) {
      req.internalUser = true;          
    }

    if (shouldIgnoreRoute(req.originalUrl, req.method) && (!someAuthAttempt || isInternalToken)) {
      next();
    } else {
      passport.authenticate("localapikey", {session: false})(req, res, next);
    }
  }

  passport.use(new LocalStrategy(strategyOptions,
    function (req, apikey, done) {
      let onSuccess = function (result) {
        const jwtToken = getAuthToken(req);
        req.application = result;
        req.tokens = { token: apikey, jwtToken };
        // if jwtToken is present obtain user from it
        if (result && result.privateKey && jwtToken) {
          const user = fetchUserFromJwtToken(jwtToken, result.privateKey);
          if (user && user.aud === 'customer') {
            req.customer = user;
          } else {
            req.user = user;
          }
        }
        // done executes Passport login and fills req.user (or an alias if userProperty is defined in root index.js)
        return done(null, result);
      };
      let onErr = function (err) { return done(err, null); };

      let result = findByApiKey(apikey, req).then(onSuccess, onErr);
      if (result.done) {
        result.done();
      }
    }
  ));

  function getAuthToken(req) {
    return req.headers.authorization ? req.headers.authorization.replace(/^Bearer /, "") : null;
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

  // if this setup is used then the endpoint will be opened, please sanitize the content if needed
  // if some auth attempt is done then authtentication will be performed
  function optionalTokenSecured(req, res, next) {
    if (isIgnoredRouteWithoutAuthAttempt(req, strategyOptions)) {
      return next();
    }
    
    return authenticateTokenMiddleware(req, res, next);
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
    processJwtToken(req, res, jwtToken, next, options);
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

  function validateJwtIfGiven(req, res, next) {
    const jwtToken = getAuthToken(req);
    if (!jwtToken) {
      return next();
    }
    return authenticateTokenMiddleware(req, res, next);
  }

  function findOneAdministrator(accountId) {
    const query = {
      accountId,
      deleted: false,
      "roles.administrator": 1,
      "locked.status": false,
    };
    return simpleDao.connect()
      .then((db) => {
        return db.collection(constants.DB_USER_COLLECTION_NAME).findOne(query);
      });
  }

  function findUserForInternalToken(application) {
    // find the "original user", using the userId of the Application found by x-api-key
    return findUserById(application.userId).then((user) => {
      if (user) {
        return user;
      }
      // the "original user" is no longer enabled, fetch a valid administrator to impersonate
      return findOneAdministrator(application.accountId);
    });
  }

  function processJwtToken(req, res, jwtToken, next, options = {}) {
    // will only assign req.user if it's not present. Because it could've been assigned previously
    const {audience = null, bypassAccount = false} = options;
    const decodedToken = decodeToken(jwtToken);

    if (isTestToken(jwtToken)) {
      if (!req.user) {
        req.user = getTestUser(jwtToken);
      }
      return next();
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
      const tokenPayload = verifyInternalToken(jwtToken, internalAuthTokenSigningSecrets);

      if (!tokenPayload) {
        logger.error("authenticateTokenMiddleware: Failed to validate internal auth token using any signing key");
        return res.status(401).send("Unauthorized");
      }
      if (bypassAccount) {
        return next();
      }

      return findUserForInternalToken(req.account)
        .then((user) => {
          assert(user, "unable to find user to impersonate");

          Reflect.deleteProperty(user, "password");

          if (!req.user) {
            req.user = Object.assign({}, user, tokenPayload);
          }
          return next();
        })
        .catch((err) => {
          logger.error(`authenticateTokenMiddleware: Error occurred finding user to impersonate for internal token. Check user ${req.account.userId} exists, or the account has at least one enabled administrator.`, err);
          return res.status(401).send("Unauthorized");
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
        // audience does not exist at api-key verification time, so if it's defined, token needs to be verified again
        if (!req.user || audience) {
          req.user = jwt.verify(jwtToken, req.account.privateKey, userTokenVerifyOptions);
        }
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

  function fetchUserFromJwtToken(jwtToken, privateKey) {
    let user = null;
    try {
      const decodedToken = decodeToken(jwtToken);
      const testToken = isTestToken(jwtToken);
      if (decodedToken) {
        const isInternalToken = decodedToken.iss === constants.INTERNAL_AUTH_TOKEN_ISSUER;
        if (!isInternalToken) {
          if (testToken) {
            user = getTestUser(jwtToken);
          } else {
            const userTokenVerifyOptions = {
              algorithms: ["HS512"],
              subject: "account_user_sign_in",
              issuer: constants.USER_AUTH_TOKEN_ISSUER,
            };
            user = jwt.verify(jwtToken, privateKey, userTokenVerifyOptions);
          }
        }
      }
    } catch (err) {
      logger.error(`Passport localapikey validation: ${err.name || 'Unexpected error'} occurred fetching the user from the jwt`, err);
    }
    return user;
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
    customerTokenSecured,
    optionalTokenSecured,
    validateJwtIfGiven
  };
};

module.exports = {
  Authenticator,
  InternalAuthTokenProvider
};
