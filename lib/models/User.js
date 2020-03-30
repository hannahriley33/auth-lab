const mongoose = require('mongoose');
const { hashSync, compare } = require('bcryptjs');
const { sign, verify } = require('jsonwebtoken');

const schema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  passwordHash: {
    type: String,
    required: true
  }
}, {
  toJSON: {
    transform: (doc, ret) => {
      delete ret.passwordHash;
    }
  }
});

// use a virtual so we never save a plain text password in our db
schema.virtual('password').set(function(password) {
  // hash the password with bcrypt
  const hash = hashSync(password, Number(process.env.SALT_ROUNDS) || 14);
  // set this.passwordHash to the hashed password
  this.passwordHash = hash;
});

// for login
schema.statics.authorize = async function({ username, password }) {
  // check that a user exists with username
  const user = await this.findOne({ username });
  if(!user) {
    // throw an error
    const error = new Error('Invalid username/password');
    error.status = 403;
    throw error;
  }

  // check that the user with username has a matching password
  const matchingPasswords = await compare(password, user.passwordHash);
  if(!matchingPasswords) {
    // throw an error
    const error = new Error('Invalid username/password');
    error.status = 403;
    throw error;
  }
  // if both conditions are true return the user
  return user;

  // otherwise throw an error
};

// for signup and login
// take a user and create a token
schema.methods.authToken = function() {
  // remove passwordHash
  // const jsonifiedUser = this.toJSON();
  // delete jsonifiedUser.passwordHash; handled by our toJSON transform
  // use jsonwebtoken to create a token for our user and return it
  const token = sign({ payload: this.toJSON() }, process.env.APP_SECRET);
  return token;
};

// mongoose document -> pojo (.toJSON())
// pojo -> mongoose document (hydrate)

// ensure auth middleware
// take a token and get a user
schema.statics.findByToken = function(token) {
  try {
    // take a token
    const { payload } = verify(token, process.env.APP_SECRET);
    // return a user who owns the token
    return Promise.resolve(this.hydrate(payload));
  } catch(e) {
    return Promise.reject(e);
  }
};

module.exports = mongoose.model('User', schema);
