/*jshint globalstrict:true, node:true, trailing:true, mocha:true unused:true */

'use strict';

var LDAP = require('../');
var assert = require('assert');
var fs = require('fs');
var ldap;

// This shows an inline image for iTerm2
// should not harm anything otherwise.
function showImage(what) {
    var encoded = what.toString('base64');

    process.stdout.write('\x1b]1337;File=size='+ what.length +
                         ';width=auto;height=auto;inline=1:' +
                         encoded + '\x07\n');
    
}


describe('LDAP', function() {
    it ('Should initialize OK', function() {
        ldap = new LDAP({
            uri: 'ldap://localhost:1234',
            base: 'dc=sample,dc=com',
            attrs: '*'
        });
    });
    it ('Should search', function(done) {
        ldap.search({
            filter: '(cn=babs)',
            scope:  LDAP.SUBTREE
        }, function(err, res) {
            assert.equal(err, undefined);
            assert.equal(res.length, 1);
            assert.equal(res[0].sn[0], 'Jensen');
            assert.equal(res[0].dn, 'cn=Babs,dc=sample,dc=com');
            done();
        });
    });
    /*    it ('Should timeout', function(done) {
        ldap.timeout=1; // 1ms should do it
        ldap.search('dc=sample,dc=com', '(cn=albert)', '*', function(err, msgid, res) {
            // assert(err !== undefined);
            ldap.timeout=1000;
            done();
        });
    }); */
    it ('Should return specified attrs', function(done) {
        ldap.search({
            base: 'dc=sample,dc=com',
            filter: '(cn=albert)',
            attrs: 'sn'
        }, function(err, res) {
            assert.notEqual(res, undefined);
            assert.notEqual(res[0], undefined);
            assert.equal(res[0].sn[0], 'Root');
            assert.equal(res[0].cn, undefined);
            done();
        });
    });
    it ('Should handle a null result', function(done) {
        ldap.search({
            base:   'dc=sample,dc=com',
            filter: '(cn=wontfindthis)',
            attrs:  '*'
        }, function(err, res) {
            assert.equal(res.length, 0);
            done();
        });
    });
    it ('Should not delete', function(done) {
        ldap.delete('cn=Albert,ou=Accounting,dc=sample,dc=com', function(err) {
            assert.notEqual(err, undefined);
            done();
        });
    });
    it ('Should findandbind()', function(done) {
        ldap.findandbind({
            base:     'dc=sample,dc=com',
            filter:   '(cn=Charlie)',
            attrs:    '*',
            password: 'foobarbaz'
        }, function(err, data) {
            assert.equal(err, undefined);
            done();
        });
    });
    it ('Should findandbind() again', function(done) {
        ldap.findandbind({
            base:     'dc=sample,dc=com',
            filter:   '(cn=Charlie)',
            attrs:    '*',
            password: 'foobarbaz'
        }, function(err, data) {
            assert.equal(err, undefined);
            done();
        });
    });
    it ('Should fail findandbind()', function(done) {
        ldap.findandbind({
            base:     'dc=sample,dc=com',
            filter:   '(cn=Charlie)',
            attrs:    'cn',
            password: 'foobarbax'
        }, function(err, data) {
            assert.notEqual(err, undefined);
            done();
        });
    });    
    it ('Should not bind', function(done) {
        ldap.bind({binddn: 'cn=Manager,dc=sample,dc=com', password: 'xsecret'}, function(err) {
            assert.notEqual(err, undefined);
            done();
        });
    });
    it ('Should bind', function(done) {
        ldap.bind({binddn: 'cn=Manager,dc=sample,dc=com', password: 'secret'}, function(err) {
            assert.equal(err, undefined);
            done();
        });
    });
    it ('Should delete', function(done) {
        ldap.delete('cn=Albert,ou=Accounting,dc=sample,dc=com', function(err) {
            assert.equal(err, undefined);
            ldap.search({
                base:   'dc=sample,dc=com',
                filter: '(cn=albert)',
                attrs:  '*'
            }, function(err, res) {
                assert(res.length == 0);
                done();
            });
        });
    });
    it ('Should add', function(done) {
        ldap.add('cn=Albert,ou=Accounting,dc=sample,dc=com', [
            {
                attr: 'cn',
                vals: [ 'Albert' ]
            },
            {
                attr: 'objectClass',
                vals: [ 'organizationalPerson', 'person' ]
            },
            {
                attr: 'sn',
                vals: [ 'Root' ]
            },
            {
                attr: 'userPassword',
                vals: [ 'e1NIQX01ZW42RzZNZXpScm9UM1hLcWtkUE9tWS9CZlE9' ]
            }
        ], function(err, res) {
            assert.equal(err, undefined);
            done();
        });

    });
    it ('Should fail to add', function(done) {
        ldap.add('cn=Albert,ou=Accounting,dc=sample,dc=com', [
            {
                attr: 'cn',
                vals: [ 'Albert' ]
            },
            {
                attr: 'objectClass',
                vals: [ 'organizationalPerson', 'person' ]
            },
            {
                attr: 'sn',
                vals: [ 'Root' ]
            },
            {
                attr: 'userPassword',
                vals: [ 'e1NIQX01ZW42RzZNZXpScm9UM1hLcWtkUE9tWS9CZlE9' ]
            }
        ], function(err, res) {
            assert.notEqual(err, undefined);
            done();
        });
    });
    it ('Should survive a slight beating', function(done) {
        var count = 0;
        for (var x = 0 ; x < 1000 ; x++) {
            ldap.search({
                base: 'dc=sample,dc=com',
                filter: '(cn=albert)',
                attrs: '*'
            }, function(err, res) {
                count++;
                if (count >= 1000) {
                    done();
                }
            });
        }
    });
    it ('Should rename', function(done) {
        ldap.rename('cn=Albert,ou=Accounting,dc=sample,dc=com', 'cn=Alberto', function(err) {
            assert.equal(err, undefined);
            ldap.rename('cn=Alberto,ou=Accounting,dc=sample,dc=com', 'cn=Albert', function(err) {
                assert.equal(err, undefined);
                done();
            });
        });
    });
    it ('Should fail to rename', function(done) {
        ldap.rename('cn=Alberto,ou=Accounting,dc=sample,dc=com', 'cn=Albert', function(err) {
            assert.notEqual(err, undefined);
            done();
        });
    });
    it ('Should modify a record', function(done) {
        ldap.modify('cn=Albert,ou=Accounting,dc=sample,dc=com', [
            { op: 'add',  attr: 'title', vals: [ 'King of Callbacks' ] },
            { op: 'add',  attr: 'telephoneNumber', vals: [ '18005551212', '18005551234' ] }
        ], function(err) {
            assert(!err);
            ldap.search(
                {
                    base: 'dc=sample,dc=com',
                    filter: '(cn=albert)',
                    attrs: '*'
                }, function(err, res) {
                    assert.equal(res[0].title[0], 'King of Callbacks');
                    assert.equal(res[0].telephoneNumber[0], '18005551212');
                    assert.equal(res[0].telephoneNumber[1], '18005551234');
                    done();
                });
        });
    });
    it ('Should fail to modify a record', function(done) {
        ldap.modify('cn=Albert,ou=Accounting,dc=sample,dc=com', [
            {
                op: 'add',
                attr: 'notInSchema',
                vals: [ 'King of Callbacks' ]
            }
        ], function(err) {
            assert.notEqual(err, undefined);
            done();
        });
    });
    it ('Should handle a binary return', function(done) {
        ldap.search({
            base: 'dc=sample,dc=com',
            filter: '(cn=babs)',
            attrs: 'jpegPhoto'
        }, function(err, res) {
            showImage(res[0].jpegPhoto[0]);
            done();
        });
    });
    it ('Should accept unicode on modify', function(done) {
         ldap.modify('cn=Albert,ou=Accounting,dc=sample,dc=com', [
             { op: 'replace',  attr: 'title', vals: [ 'ᓄᓇᕗᑦ ᒐᕙᒪᖓ' ] }
         ], function(err) {
             assert(!err, 'Bad unicode');
             ldap.search({
                 base: 'dc=sample,dc=com',
                 filter: '(cn=albert)',
                 attrs: '*'
             }, function(err, res) {
                 assert.equal(res[0].title[0], 'ᓄᓇᕗᑦ ᒐᕙᒪᖓ');
                 done();
             });
         });
    });
    it ('Should search with unicode', function(done) {
        ldap.search({
            base: 'dc=sample,dc=com',
            filter: '(title=ᓄᓇᕗᑦ ᒐᕙᒪᖓ)',
            attrs: '*'
            }, function(err, res) {
                assert.equal(res[0].dn, 'cn=Albert,ou=Accounting,dc=sample,dc=com');
                done();
            });
    });
});
