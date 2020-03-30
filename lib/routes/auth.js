const { Router } = require('express');
const ensureAuth = require('../middleware/ensure-auth');
const User = require('../models/User');

const ONE_DAY_IN_MS = 1000 * 60 * 60 * 24;

module.exports = Router() 
  .post('/signup', (req, res, next) => {
    // create a new user
    User
      .create(req.body) // hash password with virtual
      .then(user => {
        // create a JWT
        const token = user.authToken();

        // send the user and JWT
        // xss
        res.cookie('session', token, {
          maxAge: ONE_DAY_IN_MS,
          httpOnly: true
        });

        res.send(user);
      })
      .catch(next);
  })

  .post('/login', (req, res, next) => {
    // check a users username and password (authorize)
    User
      .authorize(req.body)
      .then(user => {
        // create JWT
        const token = user.authToken();
        // send the user and JWT

        res.cookie('session', token, {
          maxAge: ONE_DAY_IN_MS,
          httpOnly: true
        });

        res.send(user);
      })
      .catch(next);
  })

  .get('/verify', ensureAuth, (req, res) => {
    // send an error if the person is NOT logged in (handled by ensureAuth middleware)

    // send the user if the person is logged in
    res.send(req.user);
  });
