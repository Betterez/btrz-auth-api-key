describe("Express integration", function () {

  let request = require("supertest"),
    expect = require("chai").expect,
    Chance = require("chance").Chance,
    chance = new Chance(),
    MockDate = require("mockdate"),
    express = require("express"),
    bodyParser = require("body-parser"),
    jwt = require("jsonwebtoken"),
    SimpleDao = require("btrz-simple-dao").SimpleDao,
    mockLogger = { info() { }, error() { } },
    constants = require("../constants"),
    { Authenticator, InternalAuthTokenProvider, audiences } = require("../"),
    app,
    testKey = "test-api-key",
    validKey = "72ed8526-24a6-497f-8949-ec7ed6766aaf",
    validKeyWithNoUser = "10967537-7ea4-46f3-a723-9822db056646",
    validKeyWithDeletedUser = "10967537-7ea4-46f3-a723-9822db055757",
    privateKey = "492a97f3-597f-4b54-84f5-f8ad3eb6ee36",
    internalAuthTokenSigningSecrets = {
      main: chance.hash(),
      secondary: chance.hash()
    },
    internalAuthTokenProvider = null,
    testUser = { _id: chance.hash(), name: "Test", last: "User" },
    testFullUser = { _id: SimpleDao.objectId(), name: "Test", last: "User", display: "Testing", password: chance.hash(), deleted: false },
    deletedUser = { _id: SimpleDao.objectId(), deleted: true },
    userTokenSigningOptions = { algorithm: "HS512", expiresIn: "2 days", issuer: "btrz-api-accounts", subject: "account_user_sign_in"},
    internalTokenSigningOptions = {
      algorithm: "HS512", expiresIn: "2 minutes",
      issuer: constants.INTERNAL_AUTH_TOKEN_ISSUER,
      audience: "betterez-app"
    },
    validToken = jwt.sign({ user: testFullUser, aud: "betterez-app"}, privateKey, userTokenSigningOptions),
    validBackofficeToken = jwt.sign({ user: testFullUser, aud: "betterez-app" }, privateKey, userTokenSigningOptions),
    validBackofficeTokenForOtherApp = jwt.sign({ user: testFullUser, aud: "other-app" }, privateKey, userTokenSigningOptions),
    validInternalToken = jwt.sign({}, internalAuthTokenSigningSecrets.main, internalTokenSigningOptions),
    validCustomerToken = jwt.sign({ customer: { _id: 1, customerNumber: "111-222-333" }, aud: "customer" }, privateKey, userTokenSigningOptions),
    testToken = "test-token",
    options,
    simpleDao;

  const apiKeys = [
    {accountId: chance.hash(), key: validKey, privateKey: privateKey, userId: testFullUser._id.toString()},
    {accountId: chance.hash(), key: validKeyWithNoUser, privateKey: chance.guid(), userId: SimpleDao.objectId().toString()},
    {accountId: chance.hash(), key: validKeyWithDeletedUser, privateKey: chance.guid(), userId: deletedUser._id.toString()},
  ];

  beforeEach(async () => {
    options = {
      "testKey": testKey,
      "testUser": testUser,
      "testToken": testToken,
      "authKeyFields" : {
        request: "apiKey"
      },
      "ignoredRoutes": [
        "^/api-docs",
        "^/ignoredsecure",
        "^/ignored-and-secure",
        "^/say-no$",
        "^/route/with/only/internal/token",
        {route: "^/ignored-get-put", methods: ["GET", "PUT"]}
      ],
      "collection": {
        "name": "apikeys",
        "property": "key"
      },
      "db": {
          "options": {
            "database": "btrzAuthApiKeyTest",
            "username": "",
            "password": ""
          },
          "uris": [
            "127.0.0.1:27017"
          ]
        },
        internalAuthTokenSigningSecrets,
      };
    let auth = new Authenticator(options, mockLogger);
    internalAuthTokenProvider = new InternalAuthTokenProvider(options);
    app = express();
    app.use(auth.initialize({userProperty: "account"}));
    app.use(auth.authenticate());
    app.use(bodyParser.json());
    app.get("/api-docs", function (req, res) {
      res.status(200).json({docs: "documents"});
    });
    app.get("/api-docs/pets", function (req, res) {
      res.status(200).json({docs: "documents"});
    });
    app.get("/hello-world", function (req, res) {
      res.status(200).json(req.account);
    });
    app.put("/ignored-get-put", function (req, res) {
      res.status(200).json(req.account);
    });
    app.get("/ignored-get-put", function (req, res) {
      res.status(200).json(req.account);
    });
    app.post("/ignored-get-put", function (req, res) {
      res.status(200).json(req.account);
    });
    app.get("/secured", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), function (req, res) {
      res.status(200).json(req.user);
    });
    app.get("/ignoredsecure", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), function (req, res) {
      res.status(200).json(req.account);
    });
    app.get("/ignored-and-secure", auth.optionalTokenSecured, function (req, res) {
      res.status(200).json(req.account);
    });    
    app.get("/backoffice", auth.tokenSecuredForBackoffice, function (req, res) {
      res.status(200).json(req.user || {message: "no token"});
    });
    app.post("/backoffice", auth.tokenSecuredForBackoffice, function (req, res) {
      res.status(200).json(req.user || {message: "no token"});
    });
    app.get("/customer", auth.customerTokenSecured, function (req, res) {
      res.status(200).json(req.user || {});
    });
    app.get("/route/with/only/internal/token", auth.tokenSecuredWithoutAccount, function (req, res) {
      res.status(200).json(req.user || {});
    });
    app.get("/allowOnlyCustomerOrBackoffice", auth.tokenSecuredForAudiences(["betterez-app", "customer"]), function (req, res) {
      res.status(200).json(req.user || {});
    });
    app.get("/validate-jwt-if-given", auth.validateJwtIfGiven, function (req, res) {
      res.status(200).json(req.user || {});
    }); 
    app.get("/gimmeTokens", function (req, res) {
      res.status(200).json(req.tokens);
    });
    app.get("/gimmeTokensSecured", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), function (req, res) {
      res.status(200).json(req.tokens);
    });
    app.get("/unsecureWithUser", function (req, res) {
      res.status(200).json(req.user);
    });
    simpleDao = new SimpleDao(options);
    const db = await simpleDao.connect();
    await db.collection(options.collection.name)
      .insertMany(apiKeys);
    await db.collection("users")
      .insertMany([testFullUser, deletedUser]);
  });

  afterEach(async () => {
    MockDate.reset();
    const db = await simpleDao.connect();
    await db.dropCollection("apikeys");
    await db.dropCollection("users");
  });

  it("should return 200 ok if no X-API-KEY is present but route should not be secured and use internal token", function (done) {
    request(app)
      .get("/api-docs")
      .set("Accept", "application/json")
      .set("Authorization", `Bearer ${validInternalToken}`)
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should return 401 if no X-API-KEY is present and route should not be secured (strict regexp)", function (done) {
    request(app)
      .get("/say-no/more")
      .set("Accept", "application/json")
      .expect(401)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should return 200 ok if no X-API-KEY is present but route should not be secured and use internal token (ignore method GET)", function (done) {
    request(app)
      .get("/ignored-get-put")
      .set("Accept", "application/json")
      .set("Authorization", `Bearer ${validInternalToken}`)
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should return 200 ok if no X-API-KEY is present but route should not be secured and use internal token (ignore method PUT)", function (done) {
    request(app)
      .put("/ignored-get-put")
      .set("Accept", "application/json")
      .set("Authorization", `Bearer ${validInternalToken}`)
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should return 200 ok if no X-API-KEY is present but route should not be secured (ignore method PUT)", function (done) {
    request(app)
      .put("/ignored-get-put")
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });  

  it("should return 401 if no X-API-KEY is present and method POST for route is secured", function (done) {
    request(app)
      .post("/ignored-get-put")
      .set("Accept", "application/json")
      .expect(401)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should return 200 ok if no X-API-KEY is present but route should not be secured and use internal token", function (done) {
    request(app)
      .get("/api-docs/pets")
      .set("Accept", "application/json")
      .set("Authorization", `Bearer ${validInternalToken}`)
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should return 401 unauthorized if no X-API-KEY header is present", function (done) {
    request(app)
      .get("/hello-world")
      .set("Accept", "application/json")
      .expect(401)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should return 401 unauthorized if X-API-KEY is not valid", function (done) {
    request(app)
      .get("/hello-world")
      .set("X-API-KEY", chance.hash())
      .set("Accept", "application/json")
      .expect(401)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate the user if HEADER X-API-KEY is valid", function (done) {
    request(app)
      .get("/hello-world")
      .set("X-API-KEY", validKey)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate the user if QS X-API-KEY is valid despite it is an ignored route", function (done) {
    request(app)
      .get(`/ignored-get-put?apiKey=${validKey}`)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate the user if QS X-API-KEY is valid", function (done) {
    request(app)
      .get(`/hello-world?apiKey=${validKey}`)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate the user if X-API-KEY is the testKey", function (done) {
    request(app)
      .get("/hello-world")
      .set("X-API-KEY", testKey)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should add the testUser into the request X-API-KEY is the testKey", function (done) {
    request(app)
      .get("/hello-world")
      .set("X-API-KEY", testKey)
      .set("Accept", "application/json")
      .expect(200)
      .expect(testUser)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should read the user from a custom key on request", function (done) {
    request(app)
      .get("/hello-world")
      .set("X-API-KEY", testKey)
      .set("Accept", "application/json")
      .expect(200)
      .expect(testUser)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should require api key header for token secured route", function (done) {
    request(app)
      .get("/secured")
      .set("Authorization", `Bearer ${validToken}`)
      .set("Accept", "application/json")
      .expect(401)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should require token in token secured route", function (done) {
    request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Accept", "application/json")
      .expect(401)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should require api key header on ignoredRoutes for token secured route", function (done) {
    request(app)
      .get("/ignoredsecure")
      .set("Authorization", `Bearer ${validToken}`)
      .set("Accept", "application/json")
      .expect(401)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  describe("#ignored-and-secure", () => {
    it("should return 200 if xapikey and jwttoken are sent for an optional token secured route", function (done) {
      request(app)
        .get("/ignored-and-secure")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });  
  
    it("should return 401 if xapikey is invalid for an optional token secured route", function (done) {
      request(app)
        .get("/ignored-and-secure")
        .set("X-API-KEY", "invalid key")
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });
    
    it("should return 401 if jwttoken is invalid for an optional token secured route", function (done) {
      request(app)
        .get("/ignored-and-secure")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer invalidtoken`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });
    
    it("should return 401 if jwttoken is ommited for an optional token secured route", function (done) {
      request(app)
        .get("/ignored-and-secure")
        .set("X-API-KEY", validKey)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });  
  
    it("should return 401 if xapikey is ommited for an optional token secured route", function (done) {
      request(app)
        .get("/ignored-and-secure")
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });
  
    it("should return 200 if no auth is attempted, the route is ignored and an optional token secured setup is used", function (done) {
      request(app)
        .get("/ignored-and-secure")
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });
  })
  
  describe("#validate-jwt-if-given", () => {
    it("should return 200 if a valid jwttoken is sent", function (done) {
      request(app)
        .get("/validate-jwt-if-given")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          done();
        });
    }); 

    it("should authenticate with token and set req.user to the token payload if a valid jwttoken is sent", function (done) {
      request(app)
        .get("/validate-jwt-if-given")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should return 200 if not jwttoken is sent", function (done) {
      request(app)
        .get("/validate-jwt-if-given")
        .set("X-API-KEY", validKey)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });  

    it("should return 401 if an invalid jwttoken is sent", function (done) {
      request(app)
        .get("/validate-jwt-if-given")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer invalid-token`)
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    }); 
  })

  it("should authenticate the user with api key and token", function (done) {
    request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `Bearer ${validToken}`)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate the user with api key and token when 'Bearer' isn't specified", function (done) {
    request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `${validToken}`)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate the user with api key and a test token", function (done) {
    request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `Bearer ${testToken}`)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate with token and set req.user to the token payload", function (done) {
    request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `Bearer ${validToken}`)
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err, response) {
        if (err) {
          return done(err);
        }
        let user = JSON.parse(response.text).user;
        expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
        done();
      });
  });

  it.skip("should not authenticate when the token issuer is not specified", () => {
    const tokenSigningOptions = Object.assign({}, userTokenSigningOptions, {issuer: undefined}),
      tokenWithNoIssuer = jwt.sign({user: testFullUser}, privateKey, tokenSigningOptions);

    return request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `Bearer ${tokenWithNoIssuer}`)
      .set("Accept", "application/json")
      .expect(401);
  });

  it("should not authenticate when the token is malformed", () => {
    const malformedToken = chance.hash();

    return request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `Bearer ${malformedToken}`)
      .set("Accept", "application/json")
      .expect(401);
  });

  context("internal auth tokens", () => {
    it("should authenticate with an api key and internal token", () => {
      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it("should authenticate with an api key and internal token signed with the secondary signing secret", () => {
      const anotherValidInternalToken = jwt.sign({}, internalAuthTokenSigningSecrets.secondary, internalTokenSigningOptions);

      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${anotherValidInternalToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it("should authenticate with an internal token, fetch the user from the database, " +
      "and assign properties of the user to req.user (excluding their hashed password)", () => {
      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .expect(({body}) => {
          const expectedUserProperties = Object.keys(testFullUser).filter((prop) => prop !== "password");
          expectedUserProperties.forEach((prop) => {
            expect(body[prop]).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()})[prop]);
          });
        });
    });

    it("should authenticate with an internal token and assign properties of the token payload to req.user ", () => {
      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .expect(({body}) => {
          const tokenPayload = jwt.decode(validInternalToken),
            expectedTokenProperties = Object.keys(tokenPayload);
          expectedTokenProperties.forEach((prop) => {
            expect(body[prop]).to.deep.equal(tokenPayload[prop]);
          });
        });
    });

    it("should require that the user exists in the database", () => {
      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKeyWithNoUser)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(401);
    });

    it("should authenticate with an internal token", () => {
      return request(app)
        .get("/route/with/only/internal/token")
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it("should authenticate with an internal token when 'Bearer' isn't specified", () => {
      return request(app)
        .get("/route/with/only/internal/token")
        .set("Authorization", `${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it("should return unauthorized if internal token is not given", () => {
      return request(app)
        .get("/route/with/only/internal/token")
        .set("Accept", "application/json")
        .expect(401);
    });

    it("should return unauthorized if internal token is not valid", () => {
      return request(app)
        .get("/route/with/only/internal/token")
        .set("Authorization", "Bearer not_valid_token")
        .set("Accept", "application/json")
        .expect(401);
    });

    it("should fail because there's no administrator user enabled to impersonate", () => {
      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKeyWithDeletedUser)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(401);
    });

    describe("with a fallback user to impersonate", () => {
      const fallbackAdministrator = {
        email: "laststanding@administrator.com",
        accountId: apiKeys[2].accountId,
        deleted: false,
        roles: {administrator: 1},
        locked: {status: false},
      };

      beforeEach(async () => {
        const db = await simpleDao.connect();
        await db.collection("users")
          .insertMany([fallbackAdministrator]);
      });

      it("should use another administrator user to impersonate", () => {
        return request(app)
          .get("/secured")
          .set("X-API-KEY", validKeyWithDeletedUser)
          .set("Authorization", `Bearer ${validInternalToken}`)
          .set("Accept", "application/json")
          .expect(200)
          .then(({body}) => {
            expect(body.email).to.equal(fallbackAdministrator.email);
          });
      });
    });
  });

  describe("tokenSecuredForBackoffice middleware", function () {

    it("should not check the token if querystring does not reference channel but fill user if a validToken is provided", function (done) {
      request(app)
        .get("/backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          const body = JSON.parse(response.text);
          expect(body.user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should not check the token if querystring does not reference channel and no valid token is provided", function (done) {
      request(app)
        .get("/backoffice")
        .set("X-API-KEY", validKey)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let message = JSON.parse(response.text).message;
          expect(message).to.equal("no token");
          done();
        });
    });

    it("should not authorize if querystring requests channel=backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channel=backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should not authorize if querystring requests channel=agency-backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channel=agency-backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should not authorize if querystring requests channels contain backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channels=websales,backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should not authorize if querystring requests channels contain agency-backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channels=websales,agency-backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should not check the token if querystring references another channel", function (done) {
      request(app)
        .get("/backoffice?channel=websales")
        .set("X-API-KEY", validKey)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let message = JSON.parse(response.text).message;
          expect(message).to.equal("no token");
          done();
        });
    });

    it("should authorize if querystring requests channel=backoffice and token is for the internal app", function (done) {
      request(app)
        .get("/backoffice?channel=backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should authorize if querystring requests channel=agency-backoffice and token is for the internal app", function (done) {
      request(app)
        .get("/backoffice?channel=agency-backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should authorize if querystring requests channels cointain agency-backoffice and token is for the internal app", function (done) {
      request(app)
        .get("/backoffice?channels=any,agency-backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should authorize if querystring requests channels cointain backoffice and token is for the internal app", function (done) {
      request(app)
        .get("/backoffice?channels=any,backoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should not check the token if body does not reference channel", function (done) {
      request(app)
        .post("/backoffice")
        .send({})
        .set("X-API-KEY", validKey)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let message = JSON.parse(response.text).message;
          expect(message).to.equal("no token");
          done();
        });
    });

    it("should not authorize if body requests channel=backoffice and token is not for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "backoffice"})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should not authorize if body requests channel=agency-backoffice and token is not for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "agency-Backoffice"})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should not authorize if body requests channels contain backoffice and token is not for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channels: ["any", "backOffice"]})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should not check the token if body references another channel", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "websales"})
        .set("X-API-KEY", validKey)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let message = JSON.parse(response.text).message;
          expect(message).to.equal("no token");
          done();
        });
    });

    it("should authorize if body requests channel=backoffice and token is for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "backoffice"})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should authorize if body requests channel=agency-backoffice and token is for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "agency-backoffice"})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should authorize if body requests channels contain backoffice and token is for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channels: ["any", "backoffice"]})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should authorize when 'Bearer' isn't specified in token", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "backoffice"})
        .set("X-API-KEY", validKey)
        .set("Authorization", `${validBackofficeToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let user = JSON.parse(response.text).user;
          expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
          done();
        });
    });

    it("should authorize the configured test token", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "websales"})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${testToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let message = JSON.parse(response.text).message;
          expect(message).to.equal("no token");
          done();
        });
    });

    describe("testing options audiences array", function () {
      beforeEach(function () {
        options.audiences = ["betterez-app", "btrz-mobile-scanner"];
      });

      it("should not authorize if querystring requests channel=backoffice and token is not for the internal app", function (done) {
        request(app)
          .get("/backoffice?channel=backoffice")
          .set("X-API-KEY", validKey)
          .set("Authorization", `Bearer ${validCustomerToken}`)
          .set("Accept", "application/json")
          .expect(401)
          .end(function (err) {
            if (err) {
              return done(err);
            }
            done();
          });
      });

      it("should not authorize if querystring requests channel=backoffice and token is for other-app", function (done) {
        request(app)
          .get("/backoffice?channel=backoffice")
          .set("X-API-KEY", validKey)
          .set("Authorization", `Bearer ${validBackofficeTokenForOtherApp}`)
          .set("Accept", "application/json")
          .expect(401)
          .end(function (err) {
            if (err) {
              return done(err);
            }
            done();
          });
      });

      it("should authorize if querystring requests channel=backoffice and token is for btrz-mobile-scanner", function (done) {
        let validBackofficeTokenForMobileApp = jwt.sign({user: testFullUser, aud: "btrz-mobile-scanner"},
          privateKey, userTokenSigningOptions);
        request(app)
          .get("/backoffice?channel=backoffice")
          .set("X-API-KEY", validKey)
          .set("Authorization", `Bearer ${validBackofficeTokenForMobileApp}`)
          .set("Accept", "application/json")
          .expect(200)
          .end(function (err, response) {
            if (err) {
              return done(err);
            }
            let user = JSON.parse(response.text).user;
            expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
            done();
          });
      });

      it("should authorize if querystring requests channel=backoffice and token is for betterez-app", function (done) {
        let validBackofficeTokenForBetterezApp = jwt.sign({user: testFullUser, aud: "betterez-app"}, privateKey, userTokenSigningOptions);
        request(app)
          .get("/backoffice?channel=backoffice")
          .set("X-API-KEY", validKey)
          .set("Authorization", `Bearer ${validBackofficeTokenForBetterezApp}`)
          .set("Accept", "application/json")
          .expect(200)
          .end(function (err, response) {
            if (err) {
              return done(err);
            }
            let user = JSON.parse(response.text).user;
            expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
            done();
          });
      });
    });
  });

  describe("customerTokenSecured middleware", function () {

    it("should fail to authenticate customer with user token", function (done) {
      request(app)
        .get("/customer")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should require API key header for customer token secured route", function (done) {
      request(app)
        .get("/customer")
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(401)
        .end(function (err) {
          if (err) {
            return done(err);
          }
          done();
        });
    });

    it("should authenticate customer with token and set customer on request", function (done) {
      request(app)
        .get("/customer")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let customer = JSON.parse(response.text).customer;
          expect(customer.customerNumber).to.equal("111-222-333");
          done();
        });
    });

    it("should authenticate customer with token when 'Bearer' isn't specified and set customer on request", function (done) {
      request(app)
        .get("/customer")
        .set("X-API-KEY", validKey)
        .set("Authorization", `${validCustomerToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .end(function (err, response) {
          if (err) {
            return done(err);
          }
          let customer = JSON.parse(response.text).customer;
          expect(customer.customerNumber).to.equal("111-222-333");
          done();
        });
    });
  });

  describe("tokenSecuredForAudiences", () => {
    function sendRequest(token, cb) {
      request(app)
        .get("/allowOnlyCustomerOrBackoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${token}`)
        .set("Accept", "application/json")
        .end(cb);
    }
    function sendRequestWithoutBearer(token, cb) {
      request(app)
        .get("/allowOnlyCustomerOrBackoffice")
        .set("X-API-KEY", validKey)
        .set("Authorization", `${token}`)
        .set("Accept", "application/json")
        .end(cb);
    }
    it("should authorize for the internal app", function (done) {
      sendRequest(validBackofficeToken, function (err, response) {
        if (err) { return done(err); }
        expect(JSON.parse(response.text).user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
        done();
      });
    });
    it("should authorize for a customer", function (done) {
      sendRequest(validCustomerToken, function (err, response) {
        if (err) { return done(err); }
        expect(JSON.parse(response.text).customer.customerNumber).to.equal("111-222-333");
        done();
      });
    });
    it("should not authorize for other app", function (done) {
      sendRequest(validBackofficeTokenForOtherApp, function (err, response) {
        if (err) { return done(err); }
        expect(response.status).to.equal(401);
        expect(response.text).to.equal("Unauthorized");
        done();
      });
    });

    it("should authorize for the internal app", function (done) {
      sendRequestWithoutBearer(validBackofficeToken, function (err, response) {
        if (err) { return done(err); }
        expect(JSON.parse(response.text).user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
        done();
      });
    });
  });

  describe("internalAuthTokenProvider", () => {
    it("should generate an auth token that is accepted by token-secured endpoints", () => {
      const internalToken = internalAuthTokenProvider.getToken();

      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${internalToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it("should cache the generated token for a period of time", () => {
      const currentTimestamp = new Date().getTime(),
        futureTimestamp = currentTimestamp + 60*12*1000 + 1000, // 12 hours and one second
        internalToken1 = internalAuthTokenProvider.getToken();
      expect(internalToken1).to.exist;

      // Confirm that the first token is cached
      const internalToken2 = internalAuthTokenProvider.getToken();
      expect(internalToken2).to.equal(internalToken1);

      // Confirm that a new token will be generated after some time has elapsed
      MockDate.set(futureTimestamp);
      const internalToken3 = internalAuthTokenProvider.getToken();
      expect(internalToken3).to.exist;
      expect(internalToken3).to.not.equal(internalToken2);
    });
  });

  describe("req.tokens & req.user", () => {
    it("should add tokens to request on non-secure endpoint", () => {
      const internalToken = internalAuthTokenProvider.getToken();

      return request(app)
        .get("/gimmeTokens")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${internalToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .then(({body}) => {
          expect(body.token).to.deep.equal(validKey);
          expect(body.jwtToken).to.deep.equal(internalToken);
        });
    });

    it("should add tokens to request on secure endpoint", () => {
      const internalToken = internalAuthTokenProvider.getToken();

      return request(app)
        .get("/gimmeTokensSecured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${internalToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .then(({body}) => {
          expect(body.token).to.deep.equal(validKey);
          expect(body.jwtToken).to.deep.equal(internalToken);
        });
    });

    it("should add only x-api-key token if Authorization header is not present", () => {
      const internalToken = internalAuthTokenProvider.getToken();

      return request(app)
        .get("/gimmeTokens")
        .set("X-API-KEY", validKey)
        .set("Accept", "application/json")
        .expect(200)
        .then(({body}) => {
          expect(body.token).to.deep.equal(validKey);
          expect(body.jwtToken).to.be.null;
        });
    });

    it("should set req.user even if the endpoint is not secured", function () {
      request(app)
        .get("/unsecureWithUser")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .then(({body}) => {
          expect(body.user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
        });
    });
  });
});
