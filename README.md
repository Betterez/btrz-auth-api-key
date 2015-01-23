# btrz-auth-api-key

This module handles api authentication using x-api-key on the Betterez platform.

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

#### Options object

The options object should have the following structure.

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

#### ignoredRoutes

And array of strings containing a regular expression to match part of the whole or route. Use this to expose an end point or group of end points to the world without the need of an X-API-KEY. Try to make your regexp as restrictive as possible to avoid exposing end points by mistake.

Ex: 

    ^/api-docs //will match /api-docs, /api-docs/pets, etc.
    ^/api-docs$ //will match /api-docs and will not match /api-docs

#### db

The db options and uris array will be used to connect to the MongoDb (single server or cluster) to check for the apikey.

The `collection.name` and `collection.property` will be used to try to find one record that contains the value provided on X-API-KEY to the service.