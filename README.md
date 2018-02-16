# btrz-auth-api-key [![Build Status](https://secure.travis-ci.org/Betterez/btrz-auth-api-key.png?branch=master)](https://travis-ci.org/Betterez/btrz-auth-api-key) [![NPM version](https://badge-me.herokuapp.com/api/npm/btrz-auth-api-key.png)](http://badges.enytc.com/for/npm/btrz-auth-api-key)

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

    const Authenticator = require("btrz-auth-api-key").Authenticator,
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
    
    const auth = new Authenticator(options);
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
    },
    internalAuthTokenProvider: { 
        getToken() { 
            //function returning an auth token suitable for service-to-service calls 
        } 
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

#### internalAuthTokenProvider

An object containing one function taking no arguments: `getToken()`, which generates an auth token suitable for service-to-service calls.  The module contains an InternalAuthTokenProvider class for this purpose:
    
    const InternalAuthTokenProvider = require("btrz-auth-api-key").InternalAuthTokenProvider,
        options = {
            internalAuthTokenSigningSecrets: {
                main: "TnrRb2IadihO"
            }
        };
        
    const internalAuthTokenProvider = new InternalAuthTokenProvider(options);
    // This instance can now be provided in the options to `new Authenticator(options)`

#### auth.tokenSecured

This middleware, when used on a route definition, validates the request includes a Bearer Token that is a valid JSON Web Token as issued by the authorization endpoint on btrz-api-accounts.

Usage:

    app.get("/secured", auth.tokenSecured, function (req, res) {
        ...
    });


#### auth.tokenSecuredForAudiences

This middleware works just like tokenSecured, but allows to pass a list of audiences. The token will be validated as usual, and will be valid if it is issued for at least one of the audiences listed.

In this example, the route will be valid for customers or backoffice users:

    app.get("/secured", auth.tokenSecuredForAudiences(["betterez-app", "customer"]), function (req, res) {
        ...
    });