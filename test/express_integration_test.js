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
   jwt = require("jsonwebtoken"),
   Authenticator = require("../"),
   app,
   testKey = "test-api-key",
   validKey = "72ed8526-24a6-497f-8949-ec7ed6766aaf",
   privateKey = "492a97f3-597f-4b54-84f5-f8ad3eb6ee36",
   testUser = {_id: chance.hash(), name: "Test", last: "User"},
   testFullUser = {_id: chance.hash(), name: "Test", last: "User", display: "Testing"},
   tokenOptions = { algorithm: "HS512", expiresIn: "2 days", issuer: "btrz-api-accounts", subject: "account_user_sign_in"},
   testToken = jwt.sign({user: testFullUser}, privateKey, tokenOptions);

  before(function (done) {
    let options = {
      "testKey": testKey,
      "testUser": testUser,
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
      .set("Authorization", `Bearer ${testToken}`)
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
      .set("Authorization", `Bearer ${testToken}`)
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
      .set("Authorization", `Bearer ${testToken}`)
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

});