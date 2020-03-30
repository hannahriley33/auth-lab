const User = require('../models/User');

module.exports = (req, res, next) => {
  // read the session cookie
  const token = req.cookies.session;
  // check our JWT
  User
    .findByToken(token)
    .then(user => {
      // set a user if the JWT is valid
      req.user = user;
      next();
    })
    // otherwise send an error
    .catch(next);
};
