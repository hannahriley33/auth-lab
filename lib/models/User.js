const mongoose = require('mongoose');
const { sign, verify } = require('jsonwebtoken');
const { hashSync, compare } = require('bcryptjs');

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

schema.virtual('password').set(function(password) {
  const hash = hashSync(password, Number(process.env.SALT_ROUNDS) || 14);
  this.passwordHash = hash;
});

schema.statics.authorize = async function({ username, password }) {
  const user = await this.findOne({ username });
  if(!user) {
    const error = new Error('Invalid username/password');
    error.status = 403;
    throw error;
  }

  const matchingPasswords = await compare(password, user.passwordHash);
  if(!matchingPasswords) {
    const error = new Error('Invalid username/password');
    error.status = 403;
    throw error;
  }
  return user;
};


schema.methods.authToken = function() {
  const token = sign({ payload: this.toJSON() }, process.env.APP_SECRET);
  return token;
};

schema.statics.findByToken = function(token) {
  try {
    
    const { payload } = verify(token, process.env.APP_SECRET);

    return Promise.resolve(this.hydrate(payload));
  } catch(e) {
    return Promise.reject(e);
  }
};

module.exports = mongoose.model('User', schema);
