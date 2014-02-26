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
  var cert = req.client.getPeerCertificate();
  console.log('AUTHENTICATE');
  console.log(cert);
  
  // TODO: Implement this
  
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
