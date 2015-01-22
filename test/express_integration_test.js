"use strict";

describe("Express integration", function () {

  let request = require("supertest"),
   Chance = require("chance").Chance,
   chance = new Chance(),
   express = require("express"),
   Authenticator = require("../"),
   app;

  before(function () {
    let options = {
      "collection": {
        "name": "apikeys",
        "property": "key"
      },
      "db": {
              "options": {
                "database": "betterez_core",
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
    app.use(auth.initialize());
    app.use(auth.authenticate());
    app.get("/hello-world", function (req, res) {
      res.status(200).json({message: "Hello cruel world!"});
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

  it("should authenticate the user if X-API-KEY is valid", function (done) {
    request(app)
      .get("/hello-world")
      .set("X-API-KEY", "cd6f9160-a24d-11e4-8292-8d15ebd36e3f")
      .set("Accept", "application/json")
      .expect(200)
      .end(function (err) {
        if (err) {
          return done(err);
        }
        done();
      });
  });

});