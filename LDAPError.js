/*jshint globalstrict:true, node:true, trailing:true, mocha:true unused:true */

'use strict';

module.exports = function LDAPError(message, code) {
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.code = code;
};

require('util').inherits(module.exports, Error);
