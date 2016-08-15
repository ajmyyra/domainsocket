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
        var domainname = domainname.utf8Data;
         
        var domain = punycode.toASCII(String(domainname || ''));
        if (!domain || domaincheck.test(domain) || domain.length < 3) {
          connection.sendUTF(domainname + ":INVALID");
          return;
        }
     
        dns.resolve(domain, function(err, addresses) {
          if (err) {
            if (err.message.match("EBADNAME")) {
              connection.sendUTF(domainname + ":INVALID");
              return;
            }
            
            if (err.message.match("ENOTFOUND") || err.message.match("ENODATA")) {
              whois.lookup(domain, function(err, whoisdata) {
                if (err) {
                  console.log("Error during whois query: " + err);
                  return;
                }
                if (whoisdata.match("WHOIS LIMIT EXCEEDED")) {
                  console.log("Whois request failed for " + domain + "\nResponse:\n" + whoisdata);
                  connection.sendUTF(domainname + ":SERVFAIL")
                  return;
                }
                
                if (whoisdata.match("Domain not found") || whoisdata.match("No match for domain") || whoisdata.match("NOT FOUND")) {
                  connection.sendUTF(domainname + ":AVAILABLE");
                  return;
                }
                else {
                  connection.sendUTF(domainname + ":UNAVAILABLE");
                  return;
                }
              });
            }
            else {
              console.log("Unspecified DNS error was encountered: " + err);
              return;
            }
            
          }
          else {
            connection.sendUTF(domainname + ":UNAVAILABLE");
            return;
          }
        });
    });
    connection.on('close', function(reasonCode, description) {
        console.log((new Date()) + ' Client ' + connection.remoteAddress + ' disconnected.');
    });
});

