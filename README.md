# btrz-auth-api-key

This module handles api authentication using an x-api-key parameter, it uses passport with the passport-localapikey strategy.
It will accept the parameter in the Header, QS or BODY.
The KEY is case sensitive. 
You can configure the KEY using the authKeyFields options, see below.

## Runtimes supported

io.js >= 1.0.3
node >= v0.11.x with the --harmony flag

### Slush

If you are using the Slush generator for [slush-btrz-service](https://www.npmjs.com/package/slush-btrz-service) this package will be included and configured by default.

### Manual installation and configuration

When creating a new API service you should include this module.

    npm install btrz-auth-api-key --save

On your index.js file when creating your application service, hook this package into the middleware:

    const Logger = require("btrz-logger").Logger,
      logger = new Logger(),
      Authenticator = require("btrz-auth-api-key").Authenticator,
      options = {
        db: {
          "options": {
              "database": "betterez_core",
              "username": "",
              "password": ""
          },
          "uris": [
            "127.0.0.1:27017"
          ]
        }, 
        collection: "apikeys",
        internalAuthTokenSigningSecrets: {
          main: "TnrRb2IadihO"
          secondary: "HuFDeLoriVp3"
        }
      };
    
    const auth = new Authenticator(options, logger);
    
    app = express();
    app.use(auth.initialize());
    app.use(auth.authenticate());

#### auth.initialize()

This method is the same as calling `passport.initialize()` if you pass an `options` object it will be used internally when calling `passport.initialize()`.

For example if you want to rename the user property of the request object (where passport will store the authenticated user), you would do this:

    auth.initialize({userProperty: "principal"});

After authentication you can just do:

    var loggedUser = req.principal;

#### Options object

The options object for the Authenticator should have the following structure.

_Notice that this is a different options object than the one passed to passport._ 

    testKey: "a-key-to-use-during-testing",
    testUser: {_id: "fake-id"},
    ignoredRoutes: ["/api-docs"],
    authKeyFields: {
        header: "X-API-KEY",
        request: "x_api_key"
    },
    collection: {
        name: "collection_name",
        property: "property_name"
        },
    db {
        options:
            database: "database_name",
            username: "username",
            password: "user_password",
        },
        uris: [
            "address:port"
        ]
    },
    internalAuthTokenSigningSecrets: {
        main: "<some_secret_string>"
        secondary: "<some_other_secret_string>"
    }
    

#### testKey

This is a key that can be set to use when Unit Testing your services. Using this key avoids the need to setup a key on a test db. 

#### testUser

This is an object with any schema. If testKey is present and testUser is present it will be returned as the authenticated user in req.user
Use this for testing.

#### ignoredRoutes

And array of strings containing a regular expression to match part of the whole or route. Use this to expose an end point or group of end points to the world without the need of an X-API-KEY. Try to make your regexp as restrictive as possible to avoid exposing end points by mistake.

Ex: 

    ^/api-docs //will match /api-docs, /api-docs/pets, etc.
    ^/api-docs$ //will match /api-docs and will not match /api-docs/

To ignore only certain HTTP methods on a route, use this syntax:

    {route: "^/api-docs$", methods: ["POST", "PUT"]}

#### authKeyFields

An object containing the possible keys to look for in the HEADERS or in the request.

The request key will be mapped to a query string or body parameter. If no options is passed the HEADER will default to `X-API-KEY` and the request will default to `x_api_key`

#### db

The db options and uris array will be used to connect to the MongoDb (single server or cluster) to check for the apikey.

The `collection.name` and `collection.property` will be used to try to find one record that contains the value provided on X-API-KEY to the service.

#### internalAuthTokenSigningSecrets

The secret keys that are used to sign the auth tokens used for internal service-to-service calls.  Two keys are provided, to allow for key rotation.

#### auth.tokenSecured

This middleware, when used on a route definition, validates the request includes a Bearer Token that is a valid JSON Web Token as issued by the authorization endpoint on btrz-api-accounts.

Usage:

    app.get("/secured", auth.tokenSecured, function (req, res) {
        ...
    });

#### auth.tokenSecuredWithoutAccount

This middleware, when used on a route definition, validates the request includes an internal Bearer Token that is a valid JSON Web Token as issued by the authorization endpoint on btrz-api-client.

With this middleware you can authenticate an internal token without using `x_api_key` adding the route to the `ignoredRoutes` list. The account and user data related to the `x_api_key` will be ignored, only validating the internal token.

Usage:

    app.get("/secured", auth.tokenSecuredWithoutAccount, function (req, res) {
        ...
    });


#### auth.tokenSecuredForAudiences

This middleware works just like tokenSecured, but allows to pass a list of audiences. The token will be validated as usual, and will be valid if it is issued for at least one of the audiences listed.

In this example, the route will be valid for customers or backoffice users:

    app.get("/secured", auth.tokenSecuredForAudiences(["betterez-app", "customer"]), function (req, res) {
        ...
    });

### Authenticating Internal service-to-service calls

The authentication middleware supports secure calls between services using a special "internal" JWT token.  This is useful in cases where one services needs to access a secure endpoint belonging to another service, and you do not have a JWT token provided by the user.

The service performing the internal request will generate an "internal" JWT token using the `InternalAuthTokenProvider` class provided by this module.  You must supply a "main" secret signing key to the `InternalAuthTokenProvider`; this will be used to sign the generated JWT token.  This signing key is a secret, and it should never be committed to the codebase: fetch the value at runtime.

When a service receives a request with an authorization token, the authentication middleware will look at the token `issuer` to determine whether it is a __user-provided__ or __internal__ token.  If an internal token is detected, the authentication middleware will attempt to verify the token signature using both the "main" and "secondary" secret signing keys.  If the token signature is verified, the authentication middleware will fetch user information using the API key provided in the request's `x-api-key` header, and populate the `req.user` object for downstream code to use.

For security reasons, internal authentication tokens are short-lived, and expire soon after they are created.  The `InternalAuthTokenProvider` regenerates the internal auth token periodically, and you should always ask it for a new token every time you make a service-to-service request.

#### Key rotation

Key rotation can be performed as follows:

1. Change the value of the `secondary` signing key to some new random string (ie. using `pwgen -s 64 1`)
2. Propagate this configuration change to all services (restart if required)
3. Wait at least a number of minutes equal to the token expiration time
4. Swap the value of the `main` and `secondary` signing keys
5. Propagate this configuration change to all services (restart if required).
6. Wait at least a number of minutes equal to the token expiration time.  After this period, all valid internal tokens are guaranteed to be signed using the new signing key.
7. Change the value of the `secondary` signing key to some new random string
8. Propagate this configuration change to all services (restart if required)

At the end of this process, both the `main` and `secondary` signing keys have been changed, and there should have been no interruption of service.  Tokens that were signed using either one of the old signing keys will no longer be accepted by the authentication middleware.
