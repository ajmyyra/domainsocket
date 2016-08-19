var fs = require('fs');
var http = require('http');
var dns = require('dns');
var whois = require('whois');
var WebSocketServer = require('websocket').server;

const punycode = require('punycode');
var domaincheck = new RegExp("[^a-z0-9-.]","i");
var config = require('./config');

var httpService = (config.ssl) ? require('https') : require('http');
var server = null;
var memcached = null;
if (config.memcached) {
  var Memcached = require('memcached');
  memcached = new Memcached(config.memcached_server, {
    retries: 10,
    retry: 1000,
    reconnect: 10000,
    idle: 5000
  });
}

var processRequest = function(request, response) {
  response.writeHead(404);
  response.end();
};

if (config.ssl) {
  server = httpService.createServer({
    key: fs.readFileSync(config.ssl_key),
    cert: fs.readFileSync(config.ssl_cert)
  }, processRequest).listen(process.env.PORT || 8080, process.env.IP || "0.0.0.0", function(){
    var addr = server.address();
    console.log("Secure websocket server (wss) listening at", addr.address + ":" + addr.port);
  });
}
else {
  server = httpService.createServer(processRequest).listen(process.env.PORT || 8080, process.env.IP || "0.0.0.0", function(){
    var addr = server.address();
    console.log("Websocket server (ws) listening at", addr.address + ":" + addr.port);
  });
  
}

var wsServer = new WebSocketServer({
    httpServer: server,
    autoAcceptConnections: false
});
 
function originIsAllowed(origin) {
  if (origin == config.allowed_origin) {
    return true;
  }
  else {
    return false;
  }
}
 
wsServer.on('request', function(request) {
    if (!originIsAllowed(request.origin)) {
      request.reject();
      console.log((new Date()) + ' Connection from origin ' + request.origin + ' rejected.');
      return;
    }
    
    var connection = request.accept('echo-protocol', request.origin);
    console.log((new Date()) + ' Connection accepted.');
    connection.on('message', function(domainname) {
        domainname = domainname.utf8Data;
         
        var domain = punycode.toASCII(String(domainname || ''));
        if (!domain || domaincheck.test(domain) || domain.length < 3) {
          connection.sendUTF(domainname + ":INVALID");
          return;
        }
        
        if (config.memcached) {
          memcached.get(domain, function (err, data) {
            if (err) {
              console.log("Error in memcache query: " + err);
              return;
            }
            else {
              if (data == 'UNAVAILABLE') {
                console.log((new Date()) + " Domain " + domainname + " unavailable per cache request.");
                connection.sendUTF(domainname + ":UNAVAILABLE");
                return;
              }
              else if (data == 'AVAILABLE') {
                console.log((new Date()) + " Domain " + domainname + " available per cache request.");
                connection.sendUTF(domainname + ":AVAILABLE");
                return;
              }
              else {
                if (data == 'undefined') {
                  console.log((new Date()) + " Cache miss for " + domainname);
                }
                else {
                  console.log((new Date()) + " Strange cache entry for " + domainname + ": " + data);
                }
              }
            }
           
            
          });
        }
     
        dns.resolveNs(domain, function(err, addresses) {
          if (err) {
            if (err.message.match("EBADNAME")) {
              console.log((new Date()) +" Domain " + domainname + " is invalid per DNS query.");
              connection.sendUTF(domainname + ":INVALID");
              return;
            }
            if (err.message.match("SERVFAIL")) {
              console.log((new Date()) + " Domain " + domainname + " is unavailable per DNS query (but isn't working).");
              if (config.memcached) {
                memcached.set(domain, 'UNAVAILABLE', 3600, function (err) {
                  console.log((new Date()) + " Problem setting cache entry for " + domain + ", error: " + err);
                });
              }
              connection.sendUTF(domainname + ":UNAVAILABLE");
              return;
            }
            
            if (err.message.match("ENOTFOUND") || err.message.match("ENODATA")) {
              whois.lookup(domain, {
                "follow":  0,
                "timeout": config.timeout
              }, function(err, whoisdata) {
                if (err) {
                  console.log((new Date()) + " Error during whois query for domain " + domainname +": " + err);
                  connection.sendUTF(domainname + ":SERVFAIL");
                  return;
                }
                if (whoisdata.match("WHOIS LIMIT EXCEEDED")) {
                  console.log((new Date()) + " Whois request failed for " + domain + "\nResponse:\n" + whoisdata);
                  connection.sendUTF(domainname + ":SERVFAIL");
                  return;
                }
                
                if (whoisdata.match("Domain not found") || whoisdata.match("No match for domain") || whoisdata.match("NOT FOUND") || whoisdata.match("Status: AVAILABLE")) {
                  console.log((new Date()) + " Domain " + domainname + " available per whois request.");
                  if (config.memcached) {
                    memcached.set(domain, 'AVAILABLE', 3600, function (err) {
                      console.log((new Date()) + " Problem setting cache entry for " + domain + ", error: " + err);
                    });
                  }
                  connection.sendUTF(domainname + ":AVAILABLE");
                  return;
                }
                else {
                  console.log((new Date()) + " Domain " + domainname + " unavailable per whois request.");
                  if (config.memcached) {
                    memcached.set(domain, 'UNAVAILABLE', 3600, function (err) {
                      console.log((new Date()) + " Problem setting cache entry for " + domain + ", error: " + err);
                    });
                  }
                  connection.sendUTF(domainname + ":UNAVAILABLE");
                  return;
                }
              });
            }
            else {
              console.log((new Date()) + "Unspecified DNS error was encountered for " + domainname+ ": " + err);
              connection.sendUTF(domainname + ":SERVFAIL");
              return;
            }
            
          }
          else {
            console.log((new Date()) + " Domain " + domainname + " unavailable per DNS request.");
            if (config.memcached) {
              memcached.set(domain, 'UNAVAILABLE', 3600, function (err) {
                console.log((new Date()) + " Problem setting cache entry for " + domain + ", error: " + err);
              });
            }
            connection.sendUTF(domainname + ":UNAVAILABLE");
            return;
          }
        });
    });
    connection.on('close', function(reasonCode, description) {
        console.log((new Date()) + ' Client ' + connection.remoteAddress + ' disconnected.');
    });
});

