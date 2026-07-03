const {describe, it, beforeEach, afterEach, mock} = require("node:test");
const assert = require("node:assert/strict");
const Chance = require("chance");
const {Authenticator, authPolicy} = require("../index");
const audiences = require("../audiences");
const chance = new Chance();

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
    mock.restoreAll();
  });

  it(`should return the correct middleware when the "USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP" authorization policy is requested`, () => {
    const spy = mock.method(authenticator, "tokenSecuredForAudiences");
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP);
    assert.strictEqual(spy.mock.callCount(), 1);
    assert.deepStrictEqual(spy.mock.calls[0].arguments, [[audiences.BETTEREZ_APP]]);
    assert.deepStrictEqual(middleware, spy.mock.calls[0].result);
  });

  it(`should return the correct middleware when the "USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_MOBILE_SCANNER" authorization policy is requested`, () => {
    const spy = mock.method(authenticator, "tokenSecuredForAudiences");
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_MOBILE_SCANNER);
    assert.strictEqual(spy.mock.callCount(), 1);
    assert.deepStrictEqual(spy.mock.calls[0].arguments, [[audiences.BETTEREZ_APP, audiences.MOBILE_SCANNER]]);
    assert.deepStrictEqual(middleware, spy.mock.calls[0].result);
  });

  it(`should return the correct middleware when the "USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_PUBLIC_SALES_APP" authorization policy is requested`, () => {
    const spy = mock.method(authenticator, "tokenSecuredForAudiences");
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_PUBLIC_SALES_APP);
    assert.strictEqual(spy.mock.callCount(), 1);
    assert.deepStrictEqual(spy.mock.calls[0].arguments, [[audiences.BETTEREZ_APP, audiences.CUSTOMER]]);
    assert.deepStrictEqual(middleware, spy.mock.calls[0].result);
  });

  it(`should return the correct middleware when the "USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_MOBILE_SCANNER_OR_PUBLIC_SALES_APP" authorization policy is requested`, () => {
    const spy = mock.method(authenticator, "tokenSecuredForAudiences");
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.USER_MUST_BE_LOGGED_IN_TO_BACKOFFICE_APP_OR_MOBILE_SCANNER_OR_PUBLIC_SALES_APP);
    assert.strictEqual(spy.mock.callCount(), 1);
    assert.deepStrictEqual(spy.mock.calls[0].arguments, [[audiences.BETTEREZ_APP, audiences.MOBILE_SCANNER, audiences.CUSTOMER]]);
    assert.deepStrictEqual(middleware, spy.mock.calls[0].result);
  });

  it(`should return the correct middleware when the "ONLY_ALLOW_REQUESTS_FROM_OTHER_BETTEREZ_SERVICES" authorization policy is requested`, () => {
    const middleware = authenticator.getMiddlewareForAuthPolicy(authPolicy.ONLY_ALLOW_REQUESTS_FROM_OTHER_BETTEREZ_SERVICES);
    assert.deepStrictEqual(middleware, authenticator.tokenSecuredForInternal);
  });

  it("should throw an error if an unrecognized authorization policy is requested", () => {
    assert.throws(() => authenticator.getMiddlewareForAuthPolicy("SOME_UNKNOWN_POLICY"), {
      message: "Unrecognized authorization policy: SOME_UNKNOWN_POLICY"
    });
  });
});
