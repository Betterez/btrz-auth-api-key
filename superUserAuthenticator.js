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

function validSuperUserHash(superUser, superUserHash) {
  if (superUser) {
    return superUserHash === crypto.createHash("sha256")
      .update(`${superUser._id}-${superUser.email}-${superUser.password}`)
      .digest("hex");
  }
  return false;
}

function SuperUserAuthenticator(dao, logger) {
  assert(dao && dao.connect, "you must provide a SimpleDao");
  assert(logger && logger.info && logger.error, "you must provide a logger");

  function superUserGenerateSignature(superUserId) {
    return getSuperUser(dao, superUserId)
      .then((superUser) => {
        if (!superUser) {  
          return {superUserId: "", superUserHash: ""};
        }
        const superUserHash = crypto.createHash("sha256")
          .update(`${superUser._id}-${superUser.email}-${superUser.password}`)
          .digest("hex");
        return {
          superUserId,
          superUserHash
        };
      }).catch((err) => {
        logger.error("Error getting superuser", err);
        return {superUserId: "", superUserHash: ""};
      });
  }

  function superUserMiddleware(req, res, next) {
    const superUserId = req && req.query ? req.query.superUserId : null;
    const superUserHash = req && req.query ? req.query.superUserHash : null;
    if (!superUserId || !superUserHash) {
      return next();
    }
    return getSuperUser(dao, superUserId)
      .then((superUser) => {
        if (validSuperUserHash(superUser, superUserHash)) {
          req.superUser = superUser;
          return next();
        }
        return next();
      })
      .catch((err) => {
        logger.error("Error getting superuser", err);
        next();
      });
  }

  return {
    superUserGenerateSignature,
    superUserMiddleware
  }
}
module.exports = {
  SuperUserAuthenticator
};
