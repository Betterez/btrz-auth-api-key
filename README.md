# btrz-auth-api-key

This module handles api authentication using an x-api-key parameter, it uses passport with the passport-localapikey strategy.
It will accept the parameter in a Header, querystring or body.

## Runtimes supported

io.js >= 1.0.3
node v0.11.x with the --harmony flag

### Yeoman

If you are using the Yeoman generator for `btrz-api-services` this package will be included and configured by default.

### Manual installation and configuration

When creating a new API service you should include this module.

    npm install btrz-auth-api-key --save

Or if not published on npm yet, add this line on the `package.json`

    "btrz-auth-api-key": "git+ssh://git@github.com:Betterez/btrz-auth-api-key.git#master",

On your index.js file when creating your application service, hook this package into the middleware:

    let Authenticator = require("btrz-auth-api-key"),
      options: {
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
        collection: "apikeys"
    };
    let auth = new Authenticator(options);
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
    ^/api-docs$ //will match /api-docs and will not match /api-docs

#### db

The db options and uris array will be used to connect to the MongoDb (single server or cluster) to check for the apikey.

The `collection.name` and `collection.property` will be used to try to find one record that contains the value provided on X-API-KEY to the service.