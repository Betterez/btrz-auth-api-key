"use strict";

function fixtureLoader() {
    var options = {
      host: "127.0.0.1",
      port: "27017",
      user: "",
      pass: ""
    };
    return require("pow-mongodb-fixtures").connect("btrzAuthApiKeyTest", options);
}

describe("Express integration", function () {

  let request = require("supertest"),
    expect = require("chai").expect,
    Chance = require("chance").Chance,
    chance = new Chance(),
    express = require("express"),
    bodyParser = require("body-parser"),
    jwt = require("jsonwebtoken"),
    Authenticator = require("../"),
    app,
    testKey = "test-api-key",
    validKey = "72ed8526-24a6-497f-8949-ec7ed6766aaf",
    privateKey = "492a97f3-597f-4b54-84f5-f8ad3eb6ee36",
    testUser = {_id: chance.hash(), name: "Test", last: "User"},
    testFullUser = {_id: chance.hash(), name: "Test", last: "User", display: "Testing"},
    tokenOptions = { algorithm: "HS512", expiresIn: "2 days", issuer: "btrz-api-accounts", subject: "account_user_sign_in"},
    validToken = jwt.sign({user: testFullUser}, privateKey, tokenOptions),
    validBackofficeToken = jwt.sign({user: testFullUser, aud: "betterez-app"}, privateKey, tokenOptions),
    validCustomerToken = jwt.sign({customer: {_id: 1, customerNumber: "111-222-333"}, aud: "customer"}, privateKey, tokenOptions),
    testToken = "test-token";

  before(function (done) {
    let options = {
      "testKey": testKey,
      "testUser": testUser,
      "testToken": testToken,
      "authKeyFields" : {
        request: "apiKey"
      },
      "ignoredRoutes": [
        "^/api-docs",
        "^/ignoredsecure",
        "^/say-no$",
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
        }
      };
    let auth = new Authenticator(options);
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
    app.get("/secured", auth.tokenSecured, function (req, res) {
      res.status(200).json(req.user);
    });
    app.get("/ignoredsecure", auth.tokenSecured, function (req, res) {
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
    fixtureLoader()
      .load({apikeys: [{accountId: chance.hash(), key: validKey, privateKey: privateKey}]}, function () {
        done();
      });
  });

  after(function (done) {
    fixtureLoader().clear(done);
  });

  it("should return 200 ok if no X-API-KEY is present but route should not be secured", function (done) {
    request(app)
      .get("/api-docs")
      .set("Accept", "application/json")
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

  it("should return 200 ok if no X-API-KEY is present but route should not be secured (ignore method GET)", function (done) {
    request(app)
      .get("/ignored-get-put")
      .set("Accept", "application/json")
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

  it("should return 200 ok if no X-API-KEY is present but route should not be secured", function (done) {
    request(app)
      .get("/api-docs/pets")
      .set("Accept", "application/json")
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

  it("should authenticate with token and set the payload on request.user", function (done) {
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
        expect(user).to.deep.equal(testFullUser);
        done();
      });
  });

  describe("tokenSecuredForBackoffice middleware", function () {

    it("should not check the token if querystring does not reference channel", function (done) {
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
          let message = JSON.parse(response.text).message;
          expect(message).to.equal("no token");
          done();
        });
    });

    it("should not authorize if querystring requests channel=backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channel=backoffice")
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

    it("should not authorize if querystring requests channel=agency-backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channel=agency-backoffice")
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

    it("should not authorize if querystring requests channels contain backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channels=websales,backoffice")
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

    it("should not authorize if querystring requests channels contain agency-backoffice and token is not for the internal app", function (done) {
      request(app)
        .get("/backoffice?channels=websales,agency-backoffice")
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

    it("should not check the token if querystring references another channel", function (done) {
      request(app)
        .get("/backoffice?channel=websales")
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
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
          expect(user).to.deep.equal(testFullUser);
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
          expect(user).to.deep.equal(testFullUser);
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
          expect(user).to.deep.equal(testFullUser);
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
          expect(user).to.deep.equal(testFullUser);
          done();
        });
    });

    it("should not check the token if body does not reference channel", function (done) {
      request(app)
        .post("/backoffice")
        .send({})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
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

    it("should not authorize if body requests channel=agency-backoffice and token is not for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "agency-Backoffice"})
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

    it("should not authorize if body requests channels contain backoffice and token is not for the internal app", function (done) {
      request(app)
        .post("/backoffice")
        .send({channels: ["any", "backOffice"]})
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


    it("should not check the token if body references another channel", function (done) {
      request(app)
        .post("/backoffice")
        .send({channel: "websales"})
        .set("X-API-KEY", validKey)
        .set("Authorization", `Bearer ${validToken}`)
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
          expect(user).to.deep.equal(testFullUser);
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
          expect(user).to.deep.equal(testFullUser);
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
          expect(user).to.deep.equal(testFullUser);
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

  });
});