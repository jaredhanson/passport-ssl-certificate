/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util');


function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('SSLCertificateStrategy requires a verify callback'); }

  passport.Strategy.call(this);
  this.name = 'ssl-certificate';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req) {
  if (!req.client.authorized) {
    console.log('NOT AUTHORIZED: ' + req.client.authorizationError);
    // TODO: Pass error information through, so that the client can be informed.
    return this.fail();
  }
  
  
  var cert = req.client.getPeerCertificate();
  if (!cert) { return this.fail(); }
  if (Object.keys(cert).length == 0) { return this.fail(); }
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(); }
    self.success(user, info);
  }
  
  if (self._passReqToCallback) {
    this._verify(req, cert, verified);
  } else {
    this._verify(cert, verified);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
