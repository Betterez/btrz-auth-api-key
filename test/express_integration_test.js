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
   Chance = require("chance").Chance,
   chance = new Chance(),
   express = require("express"),
   Authenticator = require("../"),
   app, validKey, testKey = "test-api-key",
   testUser = {_id: chance.hash(), name: "Test", last: "User"};

  before(function (done) {
    let options = {
      "testKey": testKey,
      "testUser": testUser,
      "authKeyFields" : {
        request: "apiKey"
      },
      "ignoredRoutes": [
        "^/api-docs",
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
    validKey = chance.hash();
    fixtureLoader()
      .load({apikeys: [{accountId: chance.hash(), key: validKey}]}, function () {
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

});