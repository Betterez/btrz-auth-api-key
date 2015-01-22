# btrz-auth-api-key

This module handles api authentication using x-api-key on the Betterez platform.

## Runtimes supported

io.js >= 1.0.3
node v0.11.x with the --harmony flag

### Yeoman

If you are using the Yeoman generator for `btrz-api-services` this package will be included and configured by default.

### Manual configuration

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

The `collection.name` and `collection.property` will be used to try to find one record that contains the value provided on X-API-KEY to the service. 