var LDAP = require('LDAP');
var fs = require('fs');

if (process.argv.length <= 2) {
   console.log('please input ldap config file');
   process.exit(1);
}

var fileName = process.argv[2];
fs.readFile(fileName, function(err, data) {

  if (err) {
    console.log(err);
    process.exit(1);
  }

  var cfg = JSON.parse(data);

  var ldap = new LDAP({
      uri: cfg.uri,
      validatecert: cfg.validatecert,
      connecttimeout: cfg.connecttimeout
  }, function(err) {
    console.log(err);
    process.exit(0);
  });
  bind_options = {
      binddn: cfg.binddn,
      password: cfg.password
  }

  ldap.bind(bind_options, function(err) {
    if (err) {
      console.log(err);
      process.exit(0);
    }
  });
  search_options = {
    scope: ldap.SUBTREE,
    base: cfg.base,
    attrs: cfg.attrs,
    filter: cfg.filter,
    sortString: cfg.sortString,
    searchRequestControlType: cfg.searchRequestControlType,
    offset: 0,
    pagesize: cfg.pagesize
  }
  var search = function(search_options, callback) {
    console.log("------------------");
    console.log("%j", search_options);
    ldap.search(search_options, function(err, data, cookie, pageResult){
        if (err) {
          console.log(err);
          callback();
        } else {
          var next = false;
          console.log("cookie: %j", cookie);
          console.log("pageResult: %j", pageResult);

          if (search_options.searchRequestControlType == ldap.SEARCH_RCTYPE_VLV) {
            // The pageResult in vlv mode always returns offset and count (or total count).
            search_options.totalsize_fromserver = pageResult.count;
            var nextOffset = search_options.offset + search_options.pagesize;
            if (pageResult.count >= nextOffset) {
              search_options.offset = nextOffset;
              next = true;
            }
            else {
              next = false;
            }

            if (cookie && cookie.bv_val) {
              search_options.cookie = cookie;
            }
          }
          else if (search_options.searchRequestControlType == ldap.SEARCH_RCTYPE_PAGE) {
            // The pageResult in paged mode may return count (or total count), depending on the server.
            if (pageResult.count != undefined)
              if (pageResult.count > 0)
                search_options.totalsize_fromserver = pageResult.count;
            
            // But you can use cookie to check whether there is any search result left
            if (cookie && cookie.bv_val) {
              next = true;
              search_options.cookie = cookie;
            }
            else {
              next = false;
            }
          }

          var i = 0;
          data.forEach(function(entry) {
            console.log(i + ": " + entry.dn);
            i++;
          })
          console.log('Found ', i , " entries");
          if (search_options.totalsize == undefined) {
            search_options.totalsize = i;
          } else {
            search_options.totalsize += i;
          }

          if (next) {
            search(search_options, callback);
          }
          else {
            callback();
          }
        }
      });
    };
  search(search_options, function(err, data, cookie, pageResult){
    console.log("Total count: ", search_options.totalsize);
    console.log("Total count from server: ", search_options.totalsize_fromserver);

    console.log("Exit ..");
    process.exit(0);
  });
});
