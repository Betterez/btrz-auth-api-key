describe("SuperUserAuthenticator", () => {
  const {expect} = require("chai");
  const {Chance} = require("chance");
  const chance = new Chance();
  const {SimpleDao} = require("btrz-simple-dao");
  const {SuperUserAuthenticator} = require("../index.js");
  const options = {
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
  const simpleDao = new SimpleDao(options);
  let superUser = null;
  const authenticator = new SuperUserAuthenticator(simpleDao, console);

  beforeEach(async () => {
    superUser = {_id: SimpleDao.objectId(), email: chance.email(), password: chance.hash(), salt: chance.hash()};
    const db = await simpleDao.connect();
    await db.collection("superUsers")
      .insertMany([superUser]);
  });

  afterEach(async () => {
    const db = await simpleDao.connect();
    await db.dropCollection("superUsers");
  });

  describe("#superUserGenerateSignature(superUserId)", () => {
    it("should generate the superUserHash for the user", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(superUser._id.toString());
      expect(superUserId).to.equal(superUser._id.toString());
      expect(superUserHash).to.be.a("string");
      expect(superUserHash.length).to.equal(64);
    });

    it("should not fail but returns nothing if superUser not found", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(SimpleDao.objectId().toString());
      expect(superUserId).to.equal("");
      expect(superUserHash).to.equal("");
    });

    it("should not fail but returns nothing if superUserId is invalid", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature("invalid");
      expect(superUserId).to.equal("");
      expect(superUserHash).to.equal("");
    });
  });

  describe("#superUserMiddleware(req, res, next)", () => {
    it("should set the superUser in the request if valid", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(superUser._id.toString());
      const req = {query: {superUserId, superUserHash}};
      const res = {};
      const next = () => {};
      await authenticator.superUserMiddleware(req, res, next);
      expect(req.superUser._id.toString()).to.equal(superUser._id.toString());
    });

    it("should not set the superUser in the request if invalid", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(superUser._id.toString());
      const req = {query: {superUserId, superUserHash: "invalid"}};
      const res = {};
      const next = () => {};
      await authenticator.superUserMiddleware(req, res, next);
      expect(req.superUser).to.equal(undefined);
    });

    it("should not set the superUser in the request if no query", async () => {
      const req = {};
      const res = {};
      const next = () => {};
      await authenticator.superUserMiddleware(req, res, next);
      expect(req.superUser).to.equal(undefined);
    });

    it("should not set the superUser in the request if no superUserId", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(superUser._id.toString());
      const req = {query: {superUserHash}};
      const res = {};
      const next = () => {};
      await authenticator.superUserMiddleware(req, res, next);
      expect(req.superUser).to.equal(undefined);
    });

    it("should not set the superUser in the request if no superUserHash", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(superUser._id.toString());
      const req = {query: {superUserId}};
      const res = {};
      const next = () => {};
      await authenticator.superUserMiddleware(req, res, next);
      expect(req.superUser).to.equal(undefined);
    });

    it("should not set the superUser in the request if superUserId is not valid", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(superUser._id.toString());
      const req = {query: {superUserId: "hello", superUserHash}};
      const res = {};
      const next = () => {};
      await authenticator.superUserMiddleware(req, res, next);
      expect(req.superUser).to.equal(undefined);
    });

    it("should not set the superUser in the request if superUserHash is not valid", async () => {
      const {superUserId, superUserHash} = await authenticator.superUserGenerateSignature(superUser._id.toString());
      const req = {query: {superUserId, superUserHash: 1}};
      const res = {};
      const next = () => {};
      await authenticator.superUserMiddleware(req, res, next);
      expect(req.superUser).to.equal(undefined);
    });
  });
});