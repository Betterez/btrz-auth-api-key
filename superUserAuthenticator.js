const crypto = require("crypto");
const assert = require("assert");

function getSuperUser(dao, superUserId) {
  return dao.connect()
    .then((db) => {
      return db.collection("superUsers")
        .findOne({
          _id: dao.objectId(superUserId)
        });
    });
}

function validSuperUserHash(superUser, hash) {
  if (superUser) {
    return hash === crypto.createHash("sha256")
      .update(`${superUser._id}-${superUser.email}-${superUser.password}`)
      .digest("hex");
  }
  return false;
}

class SuperUserAuthenticator {
  constructor(dao, logger) {
    assert(dao && dao.connect, "you must provide a SimpleDao");
    assert(logger && logger.info && logger.error, "you must provide a logger");
    this.dao = dao;
    this.logger = logger;
  }

  superUserGenerateSignature(superUserId) {
    return getSuperUser(this.dao, superUserId)
      .then((superUser) => {
        if (!superUser) {  
          return {superUserId: "", hash: ""};
        }
        const hash = crypto.createHash("sha256")
          .update(`${superUser._id}-${superUser.email}-${superUser.password}`)
          .digest("hex");
        return {
          superUserId,
          hash
        };
      }).catch((err) => {
        this.logger.error("Error getting superuser", err);
        return {superUserId: "", hash: ""};
      });
  }

  superUserMiddleware(req, res, next) {
    const superUserId = req && req.query ? req.query.superUserId : null;
    const hash = req && req.query ? req.query.superUserHash : null;
    if (!superUserId || !hash) {
      return next();
    }
    return getSuperUser(this.dao, superUserId)
      .then((superUser) => {
        if (validSuperUserHash(superUser, hash)) {
          req.superUser = superUser;
          return next();
        }
        return next();
      })
      .catch((err) => {
        this.logger.error("Error getting superuser", err);
        next();
      });
  }
}
module.exports = {
  SuperUserAuthenticator
};
