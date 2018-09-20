/*jshint globalstrict:true, node:true, trailing:true, unused:true */

'use strict';

var binding = require('bindings')('LDAPCnx');
var LDAPError = require('./LDAPError');
var GID = 0;
var LOG_PREFIX = "nodeldap: connId: ";
var LOG_ENABLE = false;

function arg(val, def) {
    if (val !== undefined) {
        return val;
    }
    return def;
}

function Stats() {
    this.lateresponses = 0;
    this.reconnects    = 0;
    this.timeouts      = 0;
    this.requests      = 0;
    this.searches      = 0;
    this.binds         = 0;
    this.errors        = 0;
    this.modifies      = 0;
    this.adds          = 0;
    this.removes       = 0;
    this.renames       = 0;
    this.disconnects   = 0;
    this.results       = 0;
    return this;
}

function LDAP(opt) {
    this.callbacks = {};
    this.defaults = {
        base:        'dc=com',
        filter:      '(objectClass=*)',
        scope:       this.SUBTREE,
        attrs:       '*',
        starttls:    false,
        ntimeout:    1000,
        autoreconnect:true
    };
    this.timeout = opt.timeout || 2000;

    this.stats = new Stats();

    if (typeof opt.reconnect === 'function') {
        this.onreconnect = opt.reconnect;
    }
    if (typeof opt.disconnect === 'function') {
        this.ondisconnect = opt.disconnect;
    }

    if (typeof opt.uri !== 'string') {
        throw new LDAPError('Missing argument');
    }
    this.defaults.uri = opt.uri;
    if (opt.base)            this.defaults.base      = opt.base;
    if (opt.filter)          this.defaults.filter    = opt.filter;
    if (opt.scope)           this.defaults.scope     = opt.scope;
    if (opt.attrs)           this.defaults.attrs     = opt.attrs;
    if (opt.connecttimeout)  this.defaults.ntimeout  = opt.connecttimeout;
    if (opt.starttls != undefined) {
      this.defaults.starttls  = opt.starttls;
    } else {
      if (this.defaults.uri.startsWith("ldaps")) {
        this.defaults.starttls = true;
      }
    }
    if (opt.autoreconnect != undefined)
      this.defaults.autoreconnect = opt.autoreconnect;

    this.ld = new binding.LDAPCnx(this.onresult.bind(this),
                                  this.onreconnect.bind(this),
                                  this.ondisconnect.bind(this));
    this.connectionId = GID;
    if (Number.MAX_SAFE_INTEGER != GID)
      GID++;
    else
      GID = 0;
    if (LOG_ENABLE) console.log(LOG_PREFIX,  this.connectionId , " initialize(", this.defaults.uri, ")")

    try {
      this.ld.initialize(this.defaults.uri, this.defaults.ntimeout, this.defaults.starttls, this.connectionId);
    } catch (e) {
      if (LOG_ENABLE) console.log(LOG_PREFIX, "failed to initialize", e);
      throw new LDAPError("Cannot initialize LDAP Connection", -1)
    }
    return this;
}

LDAP.prototype.onresult = function(errCode, errMsg, msgid, data, cookie, pageResult) {
    this.stats.results++;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", onresult()");
    if (this.callbacks[msgid]) {
        clearTimeout(this.callbacks[msgid].timer);
        if (errMsg) {
          var sp = errMsg.indexOf('\n');
          var errCodeStr = errMsg;
          var errDetailMsg;
          if (sp > 0) {
            errCodeStr = errMsg.substring(0, sp - 1);
            errDetailMsg = errMsg.substring(sp + 1, errMsg.length);
            if (LOG_ENABLE) 
              console.log(LOG_PREFIX, this.connectionId, 
                ", errCode:",  errCode, 
                ", errCodeStr:", errCodeStr,
                ", errMessage:", errDetailMsg);
          } else {
            if (LOG_ENABLE) 
              console.log(LOG_PREFIX, this.connectionId,
                ", errCode:",  errCode, 
                ", errCodeStr:", errCodeStr);
          }
          this.callbacks[msgid](new LDAPError(errCodeStr, errCode, errDetailMsg), data, cookie, pageResult);
        } else {
          this.callbacks[msgid](errMsg, data, cookie, pageResult);
        }
        delete this.callbacks[msgid];
    } else {
        this.stats.lateresponses++;
    }
};

LDAP.prototype.onreconnect = function() {
    this.stats.reconnects++;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", onreconnect()");
    // default reconnect callback does nothing
};

LDAP.prototype.ondisconnect = function() {
    this.stats.disconnects++;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", ondisconnect()");
    // default reconnect callback does nothing
    if (this.ld == undefined || this.closing == true) {
      // disconnected by close()
      if (LOG_ENABLE) console.log(LOG_PREFIX,  this.connectionId, " onDisconnect: disconnected by close()");
    } else {
      if (LOG_ENABLE) console.log(LOG_PREFIX,  this.connectionId, " onDisconnect: autoreconnect");
      reconnect(this.ld, this.connectionId, this.defaults);
    }
};

function reconnect(ld, connectionId, options) {
  if (LOG_ENABLE) console.log(LOG_PREFIX, connectionId, ", reconnect(", options.uri, ")");
  if (options.autoreconnect)
    try {
      ld.initialize(options.uri, connectionId, options.ntimeout, options.starttls);
      ld.bind(options.bindOpt.binddn, options.bindOpt.password)
    } catch (e) {
      if (LOG_ENABLE) console.log(LOG_PREFIX,  "Failed to reconnect", e);
    }
}

LDAP.prototype.remove = LDAP.prototype.delete  = function(dn, fn) {
    this.stats.removes++;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", remove()");
    if (typeof dn !== 'string' ||
        typeof fn !== 'function') {
        throw new LDAPError('Missing argument');
    }
    return this.enqueue(this.ld.delete(dn), fn);
};

LDAP.prototype.bind = LDAP.prototype.simplebind = function(opt, fn) {
    this.stats.binds++;
    if (typeof opt          === 'undefined' ||
        typeof opt.binddn   !== 'string' ||
        typeof opt.password !== 'string' ||
        typeof fn           !== 'function') {
        throw new LDAPError('Missing argument');
    }
    this.defaults.bindOpt = opt;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", bind(", opt.binddn, ")");
    return this.enqueue(this.ld.bind(opt.binddn, opt.password), fn);
};

LDAP.prototype.add = function(dn, attrs, fn) {
    this.stats.adds++;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", add()");
    if (typeof dn    !== 'string' ||
        typeof attrs !== 'object') {
        throw new LDAPError('Missing argument');
    }
    return this.enqueue(this.ld.add(dn, attrs), fn);
};

LDAP.prototype.search = function(opt, fn) {
    this.stats.searches++;
    var srcType = DEFAULT_BINDING_SRC;
    if (opt.searchRequestControlType) {
      var srcTypeStr = opt.searchRequestControlType.toLowerCase();
      if (srcTypeStr == LDAP.prototype.SEARCH_RCTYPE_VLV) {
        srcType = VIRTUAL_LIST_VIEW_BINDING_SRC;
        if (opt.sortString == undefined || opt.sortString.length == 0) {
          throw new LDAPError("VLV control requires server side sort control");
        }
      }
      else if (srcTypeStr == LDAP.prototype.SEARCH_RCTYPE_PAGE) {
        srcType = SIMPLE_PAGED_RESULTS_BINDING_SRC;
        if (opt.sortString !== undefined && opt.sortString.length >= 0) {
          throw new LDAPError("Cannot use both pagedResults control and server side sort control");
        }
      }
    }
    else {
      if (opt.pagesize != undefined && opt.pagesize > 0) {
        if (opt.sortString != undefined && opt.sortString.length > 0) {
          srcType = VIRTUAL_LIST_VIEW_BINDING_SRC;
        } else {
          srcType = SIMPLE_PAGED_RESULTS_BINDING_SRC;
        }
      }
    }
    if (LOG_ENABLE) console.log(LOG_PREFIX,  this.connectionId, 
                                " search(", 
                                  "base:", arg(opt.base   , this.defaults.base),
                                  ", filter:", arg(opt.filter , this.defaults.filter),
                                  ", attrs:", arg(opt.attrs  , this.defaults.attrs),
                                  ", scope:", arg(opt.scope  , this.defaults.scope),
                                  ", controls:", opt.controls || [],
                                  ", srcType:", srcType,
                                  ", pageSize:", opt.pagesize,
                                  ", cookie:", opt.cookie,
                                  ", offset:", opt.offset,
                                  ", sortString,:", (srcType != SIMPLE_PAGED_RESULTS_BINDING_SRC) ? opt.sortString : null,
                                ")");
    return this.enqueue(this.ld.search(arg(opt.base   , this.defaults.base),
                                       arg(opt.filter , this.defaults.filter),
                                       arg(opt.attrs  , this.defaults.attrs),
                                       arg(opt.scope  , this.defaults.scope),
                                       opt.controls || [],
                                       srcType,
                                       opt.pagesize,
                                       opt.cookie,
                                       opt.offset,
                                       (srcType != SIMPLE_PAGED_RESULTS_BINDING_SRC) ? opt.sortString : null
                                       ), fn);
};

LDAP.prototype.rename = function(dn, newrdn, fn) {
    this.stats.renames++;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", rename()");
    if (typeof dn     !== 'string' ||
        typeof newrdn !== 'string' ||
        typeof fn     !== 'function') {
        throw new LDAPError('Missing argument');
       }
    return this.enqueue(this.ld.rename(dn, newrdn), fn);
};

LDAP.prototype.modify = function(dn, ops, fn) {
    this.stats.modifies++;
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", modify()");
    if (typeof dn  !== 'string' ||
        typeof ops !== 'object' ||
        typeof fn  !== 'function') {
        throw new LDAPError('Missing argument');
    }
    return this.enqueue(this.ld.modify(dn, ops), fn);
};

LDAP.prototype.findandbind = function(opt, fn) {
    if (opt          === undefined ||
        opt.password === undefined)  {
            throw new Error('Missing argument');
        }
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", findandbind()", opt);
    this.search(opt, function(err, data) {
        if (err) {
            fn(err);
            return;
        }
        if (data === undefined || data.length != 1) {
            fn(new LDAPError('Search returned ' + data.length + ' results, expected 1'));
            return;
        }
        if (this.auth_connection === undefined) {
            this.auth_connection = new LDAP(this.defaults);
        }
        var dn;
        if (opt.attrs && opt.attrs.length) {
          opt.attrs.forEach(function(key) {
            if (data[0][key] && data[0][key].length) {
              dn = data[0][key][0];
            }
          });
        }
        if (!dn) {
          dn = data[0].dn;
        }
        this.auth_connection.bind({ binddn: dn, password: opt.password }, function(err) {
            if (err) {
                fn(err);
                return;
            }
            fn(undefined, data[0]);
        }.bind(this));
    }.bind(this));
};

LDAP.prototype.close = function() {
    this.closing = true;
    if (this.auth_connection !== undefined) {
        this.auth_connection.close();
    }
    if (this.ld !== undefined) {
      this.ld.close();
      this.ld = undefined;
    }
    if (LOG_ENABLE) console.log(LOG_PREFIX,  this.connectionId, " close() ");
    this.closing = false;
 };

LDAP.prototype.enqueue = function(msgid, fn) {
    if (msgid == -1) {
          process.nextTick(function() {
            var errStr, errCode;
            if (this.ld != undefined) {
              errStr = this.ld.errorstring().trim();
              errCode = this.ld.errorno();
            }
            if (LOG_ENABLE) console.log(LOG_PREFIX,  this.connectionId, errCode, errStr);
            if (errCode != undefined) {
              if (errCode == 50) {
                // Insufficient access
                if (LOG_ENABLE) console.log(LOG_PREFIX, "Insufficient access. Close this connection.")
                this.ld.close();
              }
            } else if (errStr.toLowerCase().indexOf('can\'t contact ldap server') >= 0) {
              if (LOG_ENABLE) console.log(LOG_PREFIX,  connectionId, " autoreconnect");
              reconnect(this.ld, this.connectionId, this.defaults);
            }
            fn(new LDAPError(errStr, (errCode == undefined) ? -1 : errCode));
            return;
        }.bind(this));
        this.stats.errors++;
        return this;
    }
    if (LOG_ENABLE) console.log(LOG_PREFIX, this.connectionId, ", enqueue()");
    fn.timer = setTimeout(function searchTimeout() {
        delete this.callbacks[msgid];
        fn(new LDAPError('Timeout'), msgid);
        this.stats.timeouts++;
    }.bind(this), this.timeout);
    this.callbacks[msgid] = fn;
    this.stats.requests++;
    return this;
};

LDAP.prototype.BASE = 0;
LDAP.prototype.ONELEVEL = 1;
LDAP.prototype.SUBTREE = 2;
LDAP.prototype.SUBORDINATE = 3;
LDAP.prototype.DEFAULT = 4;
// Search Request Control Type
LDAP.prototype.SEARCH_RCTYPE_VLV = "vlv";
LDAP.prototype.SEARCH_RCTYPE_PAGE = "pagedresults";

var DEFAULT_BINDING_SRC = 0;
var SIMPLE_PAGED_RESULTS_BINDING_SRC = 1;
var VIRTUAL_LIST_VIEW_BINDING_SRC = 2;

module.exports = LDAP;
