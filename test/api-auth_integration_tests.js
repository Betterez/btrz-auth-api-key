describe("API auth integration tests", () => {
  const request = require("supertest");
  const expect = require("chai").expect;
  const Chance = require("chance").Chance;
  const chance = new Chance();
  const express = require("express");
  const bodyParser = require("body-parser");
  const jwt = require("jsonwebtoken");
  const SimpleDao = require("btrz-simple-dao").SimpleDao;
  const mockLogger = {info() {}, error() {}};
  const constants = require("../constants");
  const nock = require("nock");
  const {Authenticator, InternalAuthTokenProvider} = require("..");
  const validKey = "72ed8526-24a6-497f-8949-ec7ed6766aaf";
  const  privateKey = "492a97f3-597f-4b54-84f5-f8ad3eb6ee36";
  const  internalAuthTokenSigningSecrets = {
    main: chance.hash(),
    secondary: chance.hash()
  };
  const testFullUser = {_id: SimpleDao.objectId(), name: "Test", last: "User", display: "Testing", password: chance.hash(), deleted: false};
  const userTokenSigningOptions = { algorithm: "HS512", expiresIn: "2 days", issuer: "btrz-api-accounts", subject: "account_user_sign_in"};
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

  before(() => {
    options = {
      "ignoredRoutes": [],
      "db": {
          "options": {
            "database": "",
            "username": "",
            "password": ""
          },
          "uris": [
          ]
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
      
    const auth = new Authenticator(options, mockLogger);
    internalAuthTokenProvider = new InternalAuthTokenProvider(options);
    app = express();
    app.use(auth.initialize({userProperty: "account"}));
    app.use(auth.authenticate());
    app.use(bodyParser.json());
    app.get("/secured", auth.tokenSecured, (req, res) => {
      res.status(200).json(req.user);
    });
  });

  it("should authenticate the user with api key and token", (done) => {
    nock(options.apiUrl)
      .get(`/${validKey}`)
      .reply(200, {
        application: applicationMock,
        user: testFullUser
      });

    request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `Bearer ${validToken}`)
      .set("Accept", "application/json")
      .expect(200)
      .end((err) => {
        if (err) {
          return done(err);
        }
        done();
      });
  });

  it("should authenticate with token and set req.user to the token payload", (done) => {
    nock(options.apiUrl)
      .get(`/${validKey}`)
      .reply(200, {
        application: applicationMock,
        user: testFullUser
      });

    request(app)
      .get("/secured")
      .set("X-API-KEY", validKey)
      .set("Authorization", `Bearer ${validToken}`)
      .set("Accept", "application/json")
      .expect(200)
      .end((err, response) => {
        if (err) {
          return done(err);
        }
        let user = JSON.parse(response.text).user;
        expect(user).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()}));
        done();
      });
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
          expect(body[prop]).to.deep.equal(Object.assign({}, testFullUser, {_id: testFullUser._id.toString()})[prop]);
        });
      });
  });
});
