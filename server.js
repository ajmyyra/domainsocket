var http = require('http');
var dns = require('dns');
var whois = require('whois');
var WebSocketServer = require('websocket').server;

const punycode = require('punycode');
var domaincheck = new RegExp("[^a-z0-9-.]","i");
var config = require('./config');

var server = http.createServer(function(request, response) {
    console.log((new Date()) + ' Received request for ' + request.url);
    response.writeHead(404);
    response.end();
});

server.listen(process.env.PORT || 8080, process.env.IP || "0.0.0.0", function(){
  var addr = server.address();
  console.log("Websocket server listening at", addr.address + ":" + addr.port);
});

var wsServer = new WebSocketServer({
    httpServer: server,
    autoAcceptConnections: false
});
 
function originIsAllowed(origin) {
  console.log('Allowed origin: ' + config.allowed_origin); //debug
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
        console.log('Received domainname: ' + domainname);
        
        var domain = punycode.toASCII(String(domainname || ''));
        if (!domain || domaincheck.test(domain) || domain.length < 3) {
          connection.sendUTF(domainname + ":INVALID");
          return;
        }
     
        dns.resolve(domain, function(err, addresses) {
          if (err) {
            console.log('Resolution for ' + domain + ' failed: ' + err.message);
            if (err.message.match("EBADNAME")) {
              console.log("Invalid domain name: " + domainname + " reduced to " + domain); //debug
              connection.sendUTF(domainname + ":INVALID");
              return;
            }
            
            if (err.message.match("ENOTFOUND") || err.message.match("ENODATA")) {
              console.log("No record was found. Making whois query."); //debug
              whois.lookup(domain, function(err, whoisdata) {
                if (err) {
                  console.log("Error during whois query: " + err);
                  return;
                }
                console.log("Whois result:\n" + whoisdata); //debug
                if (whoisdata.match("Domain not found")) {
                  connection.sendUTF(domainname + ":AVAILABLE");
                }
                else {
                  connection.sendUTF(domainname + ":UNAVAILABLE");
                }
                return;
              });
            }
            
            console.log("Unspecified error was encountered: " + err);
            return;
          }
          else {
            console.log('Domain is not available. Response: ' + addresses); //debug
            connection.sendUTF(domainname + ":UNAVAILABLE");
            return;
          }
        });
    });
    connection.on('close', function(reasonCode, description) {
        console.log((new Date()) + ' Client ' + connection.remoteAddress + ' disconnected.');
    });
});

