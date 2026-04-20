const {describe, it, beforeEach, afterEach} = require("node:test");
const assert = require("node:assert/strict");

describe("API auth integration tests", () => {
  const request = require("supertest");
  const Chance = require("chance").Chance;
  const chance = new Chance();
  const express = require("express");
  const bodyParser = require("body-parser");
  const jwt = require("jsonwebtoken");
  const SimpleDao = require("btrz-simple-dao").SimpleDao;
  const mockLogger = {info() {}, error() {}};
  const constants = require("../constants");
  const nock = require("nock");
  const {Authenticator, InternalAuthTokenProvider, audiences} = require("..");
  const validKey = "72ed8526-24a6-497f-8949-ec7ed6766aaf";
  const  privateKey = "492a97f3-597f-4b54-84f5-f8ad3eb6ee36";
  const  internalAuthTokenSigningSecrets = {
    main: chance.hash(),
    secondary: chance.hash()
  };
  const testFullUser = {_id: SimpleDao.objectId(), name: "Test", last: "User", display: "Testing", password: chance.hash(), deleted: false};
  const userTokenSigningOptions = { algorithm: "HS512", expiresIn: "2 days", issuer: "btrz-api-accounts", subject: "account_user_sign_in", audience: "betterez-app"};
  const internalTokenSigningOptions = {
    algorithm: "HS512",
    expiresIn: "2 minutes",
    issuer: constants.INTERNAL_AUTH_TOKEN_ISSUER,
    audience: "betterez-app"
  };
  const validToken = jwt.sign({user: testFullUser}, privateKey, userTokenSigningOptions);
  const validInternalToken = jwt.sign({}, internalAuthTokenSigningSecrets.main, internalTokenSigningOptions);
  const applicationMock = {accountId: chance.hash(), key: validKey, privateKey: privateKey, userId: testFullUser._id.toString()};

  let app = null;
  let options = null;
  let auth = null;
  let internalAuthTokenProvider = null;

  describe("Using API Auth", () => {
    beforeEach(() => {
      options = {
        ignoredRoutes: [],
        db: {
          options: {
            database: "",
            username: "",
            password: ""
          },
          uris: []
        },
        internalAuthTokenSigningSecrets,
        apiAuth: true,
        apiUrl: chance.url(),
        internalAuthTokenProvider: {
          getToken: () => {
            return validInternalToken;
          }
        }
      };

      auth = new Authenticator(options, mockLogger);
      internalAuthTokenProvider = new InternalAuthTokenProvider(options);
      app = express();
      app.use(auth.initialize({userProperty: "account"}));
      app.use(auth.authenticate());
      app.use(bodyParser.json());
      app.get("/secured", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), (req, res) => {
        res.status(200).json(req.user);
      });
    });

    it("should authenticate the user with api key and token", async () => {
      nock(options.apiUrl)
        .get(`/${validKey}`)
        .reply(200, {
          application: applicationMock,
          user: testFullUser
        });

      await request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it("should return 401 as the key was not found", async () => {
      nock(options.apiUrl)
        .get("/wrongKey")
        .reply(400);

      await request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(401);
    });

    it("should authenticate with token and set req.user to the token payload", async () => {
      nock(options.apiUrl)
        .get(`/${validKey}`)
        .reply(200, {
          application: applicationMock,
          user: testFullUser
        });

      const response = await request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200)
        ;

      const user = JSON.parse(response.text).user;
      assert.deepStrictEqual(user, Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
    });

    it("should authenticate with an api key and internal token", () => {
      nock(options.apiUrl)
        .get(`/${validKey}`)
        .reply(200, {
          application: applicationMock,
          user: testFullUser
        });

      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it(`should authenticate with an internal token, 
        get the user from the API and assign properties of the user to req.user 
        (excluding its hashed password)`, () => {
      nock(options.apiUrl)
        .get(`/${validKey}`)
        .reply(200, {
          application: applicationMock,
          user: testFullUser
        });

      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .expect(({body}) => {
          const expectedUserProperties = Object.keys(testFullUser).filter((prop) => prop !== "password");
          expectedUserProperties.forEach((prop) => {
            assert.deepStrictEqual(body[prop], Object.assign({}, testFullUser, {_id: testFullUser._id.toString()})[prop]);
          });
        });
    });
  });

  describe("Using Mongo Auth", () => {

    let options = {
      ignoredRoutes: [],
      internalAuthTokenSigningSecrets,
      collection: {
        name: "applications",
        property: "key"
      },
      db: {
        options: {
          database: "btrzAuthApiKeyTest",
          username: "",
          password: ""
        },
        uris: [
          "127.0.0.1:27017"
        ]
      },
      internalAuthTokenProvider: {
        getToken: () => {
          return validInternalToken;
        }
      }
    };

    const simpleDao = new SimpleDao(options);

    beforeEach( async () => {
      auth = new Authenticator(options, mockLogger);
      internalAuthTokenProvider = new InternalAuthTokenProvider(options);
      app = express();
      app.use(auth.initialize({userProperty: "account"}));
      app.use(auth.authenticate());
      app.use(bodyParser.json());

      const db = await simpleDao.connect();
      await db.collection("applications")
        .insertMany([applicationMock]);
      await db.collection("users")
        .insertMany([testFullUser]);

    });

    afterEach( async() => {
      const db = await simpleDao.connect();
      await db.dropCollection("users");
      await db.dropCollection("applications");
    });

    it("should authenticate the user with api key and token", async () => {
      app.get("/secured", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), (req, res) => {
        res.status(200).send(req.user);
      });

      await request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it("should return 401 as the key was not found", async () => {
      await request(app)
        .get("/secured")
        .set("X-API-KEY", "invalid")
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(401);
    });

    it("should authenticate with token and set req.user to the token payload", async () => {

      app.get("/secured", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), (req, res) => {
        assert.deepStrictEqual(req.user.user._id, testFullUser._id.toString());
        res.status(200).send(req.user);
      });

      const response = await request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
        .set("Accept", "application/json")
        .expect(200)
        ;
      const user = JSON.parse(response.text).user;
      assert.deepStrictEqual(user, Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
    });

    it("should authenticate with an api key and internal token", () => {

      app.get("/secured", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), (req, res) => {
        assert.deepStrictEqual(req.user._id, testFullUser._id.toString());
        res.status(200).send(req.user);
      });

      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200);
    });

    it(`should authenticate with an internal token, 
        get the user from the API and assign properties of the user to req.user 
        (excluding its hashed password)`, () => {

      app.get("/secured", auth.tokenSecuredForAudiences([audiences.BETTEREZ_APP]), (req, res) => {
        assert.deepStrictEqual(req.user._id, testFullUser._id.toString());
        res.status(200).send(req.user);
      });

      return request(app)
        .get("/secured")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validInternalToken}`)
        .set("Accept", "application/json")
        .expect(200)
        .expect(({body}) => {
          const expectedUserProperties = Object.keys(testFullUser).filter((prop) => prop !== "password");
          expectedUserProperties.forEach((prop) => {
            assert.deepStrictEqual(body[prop], Object.assign({}, testFullUser, {_id: testFullUser._id.toString()})[prop]);
          });
        });
    });
  });

});
