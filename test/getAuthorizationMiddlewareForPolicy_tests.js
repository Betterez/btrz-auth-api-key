"use strict";
const chai = require("chai");
const {expect} = require("chai");
const Chance = require("chance");
const sinon = require("sinon");
const sinonChai = require("sinon-chai");
const {Authenticator, authPolicy} = require("../index");
const audiences = require("../audiences");
const chance = new Chance();

chai.use(sinonChai);

const  internalAuthTokenSigningSecrets = {
  main: chance.hash(),
  secondary: chance.hash()
};
const mockLogger = {info() {}, error() {}};

describe("getMiddlewareForAuthPolicy", () => {
  let authenticator;
  let authenticatorOptions;

  beforeEach(() => {
    authenticatorOptions = {
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
          return chance.hash();
        }
      }
    };
    authenticator = new Authenticator(authenticatorOptions, mockLogger);
  });

  afterEach(() => {
    sinon.restore();
  });

  it(`should return the correct middleware when the "USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP" authorization policy is requested`, () => {
    sinon.spy(authenticator, "tokenSecuredForAudiences");
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP);
    expect(authenticator.tokenSecuredForAudiences).to.have.been.calledOnceWith([audiences.BETTEREZ_APP]);
    expect(middleware).to.eql(authenticator.tokenSecuredForAudiences.returnValues[0]);
  });

  it(`should return the correct middleware when the "USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_MOBILE_SCANNER" authorization policy is requested`, () => {
    sinon.spy(authenticator, "tokenSecuredForAudiences");
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_MOBILE_SCANNER);
    expect(authenticator.tokenSecuredForAudiences).to.have.been.calledOnceWith([audiences.BETTEREZ_APP, audiences.MOBILE_SCANNER]);
    expect(middleware).to.eql(authenticator.tokenSecuredForAudiences.returnValues[0]);
  });

  it(`should return the correct middleware when the "ONLY_ALLOW_REQUESTS_FROM_OTHER_BETTEREZ_SERVICES" authorization policy is requested`, () => {
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.ONLY_ALLOW_REQUESTS_FROM_OTHER_BETTEREZ_SERVICES);
    expect(middleware).to.eql(authenticator.tokenSecuredForInternal);
  });

  it("should throw an error if an unrecognized authorization policy is requested", () => {
    expect(() => authenticator.getMiddlewareForAuthPolicy("SOME_UNKNOWN_POLICY"))
      .to.throw("Unrecognized authorization policy: SOME_UNKNOWN_POLICY");
  });
});
