'use strict';

const fs = require('fs');
const http = require('http');
const dns = require('dns');
const whois = require('whois');

const WebSocketServer = require('websocket').server;

const punycode = require('punycode');
const domaincheck = new RegExp("[^a-z0-9-.]","i");
const anyways = (promise) => promise.then((value) => ({value})).catch((error) => ({error}));
const config = require('./config');

const tsFormat = () => (new Date()).toLocaleTimeString();
const winston = require('winston');
const logger = new (winston.Logger)({
  transports: [
    new (winston.transports.Console)({
      timestamp: tsFormat,
      colorize: true,
      level: config.debug ? 'debug' : 'info',
    })
  ]
});
process.on('unhandledRejection', error => {
  logger.error("A promise was rejected but the error wasn't handled:", error)
})

var httpService = (config.ssl) ? require('https') : require('http');
var server = null;
var memcached = null;

if (config.memcached) {
  var Memcached = require('memcached');
  memcached = new Memcached(config.memcached_server, {
    timeout: 2000,
    retries: 0,
    retry: 10000,
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
  }, processRequest).listen(config.serverport || 8080, config.serverip || "0.0.0.0", function(){
    var addr = server.address();
    logger.info("Secure websocket server (wss) listening at", addr.address + ":" + addr.port);
  });
}
else {
  server = httpService.createServer(processRequest).listen(config.serverport || 8080, config.serverip || "0.0.0.0", function(){
    var addr = server.address();
    logger.info("Websocket server (ws) listening at", addr.address + ":" + addr.port);
  });
}

var wsServer = new WebSocketServer({
  httpServer: server,
  autoAcceptConnections: false
});

function checkMemcache(domain) {
  return new Promise((resolve, reject) => {
    if (config.memcached) {
      memcached.get(domain, (err, data) => {
        if (err) {
          logger.debug("Error in memcache query for domain", domain + ":", err);
          reject();
        } 
        logger.debug("Result from memcached for domain", domain + ":", data);
        resolve(data);
      })
    }
    else {
      logger.debug("Memcache not configured, rejecting cache check.");
      reject();
    }
  })
}

function addToMemcache(domain, state) {
  return new Promise((resolve, reject) => {
    if (config.memcached) {
      memcached.set(domain, state, 3600, (err) => {
        if (err) {
          logger.debug("Can't insert state", state, "to memcached for domain", domain + ", error:", err);
          reject();
        }
        logger.debug("Inserted state", state, "to memcached for domain", domain);
        resolve();
      })
    }
    else {
      logger.debug("Memcache not configured, rejecting cache insert.");
    }
  })
}

function checkDNS(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveNs(domain, (err, addresses) => {
      if (err) {
        logger.debug("DNS check for", domain, "failed:", err);
        reject(err);
      }
      else {
        logger.debug("DNS check for", domain + ":", addresses);
        resolve();
      }
    })
  })
}

function checkWhois(domain) {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, {
      'follow':  0
    }, (err, whoisdata) => {
      if (err) {
        logger.error('Error during whois query for domain', domainname +':', err);
        reject();
      }
      whoisdata = whoisdata.toLowerCase();

      if (whoisdata.match('whois limit exceeded') || 
      whoisdata.match('request is being rate limited') || 
      whoisdata.match('quota exceeded')) {
        logger.error('Whois request failed for', domain, 'with response:', whoisdata);
        reject();
      }

      resolve(whoisdata);
    })
  })
}

function originIsAllowed(origin) {
  for (var orig in config.allowed_origin) {
        logger.debug('Checking', origin,  'against', config.allowed_origin[orig]);
        if (origin === config.allowed_origin[orig]) {
            return true;
        }
  }

  return false;
}

function whoisNotfound(whoisdata) {
  const whoisresult = JSON.stringify(whoisdata);

  if (whoisresult.includes("domain not found") ||
      whoisresult.includes("no match for") ||
      whoisresult.includes("not found") ||
      whoisresult.includes("status: available") ||
      whoisresult.includes("no domain exists") ||
      whoisresult.includes("no data found") ||
      whoisresult.includes("domain status: no object found") ||
      whoisresult.includes("object does not exist") ||
      whoisresult.includes("domain status: free") ||
      whoisresult.includes("domain name has not been registered")) {
    return true;
  }
  else {
    return false;
  }
}
 
wsServer.on('request', function(request) {
  
  if (!originIsAllowed(request.origin)) {
    request.reject();
    logger.info('Client', request.remoteAddress, 'from', request.origin, 'rejected.');
    return;
  }
    
  var connection = request.accept('echo-protocol', request.origin);
  logger.info('Client', connection.remoteAddress, 'from', request.origin, 'connected.');

  connection.on('message', function(domainname) {
    domainname = domainname.utf8Data;
    var status;
    logger.debug('Whois request received for', domainname);
          
    var domain = punycode.toASCII(String(domainname || ''));
    if (!domain || domaincheck.test(domain) || domain.length < 3) {
      connection.sendUTF(domainname + ":INVALID");
      return;
    }

    anyways(checkMemcache(domainname)).then((result, error) => {
      if (result && result.value != undefined) {
        status = result.value;
        logger.info(connection.remoteAddress, 'DOMAINSTATUS', domainname + ':', status, '(from Memcached)');
        connection.sendUTF(domainname + ':' + status);
        return;
      }
        
      checkDNS(domainname).then((dnsresult) => {
        status = 'UNAVAILABLE';
        logger.info(connection.remoteAddress, 'DOMAINSTATUS', domainname + ':', status, '(from DNS)');
        if (config.memcached) {
          addToMemcache(domainname, status).catch((err) => {
            logger.error('Error when saving result for', domainname + ':', err);
          })
        }
        connection.sendUTF(domainname + ':' + status);
        return;
      }).catch((err) => {
        
        // checking for known statuses that indicate a domain is taken
        if (err.message.includes('EBADNAME')) {
          status = 'INVALID';
          logger.debug('Domain', domainname, 'is invalid per DNS query.');
        }
        if (err.message.includes("ESERVFAIL")) {
          logger.debug('Domain', domainname, 'is unavailable per DNS query (but is not working).');
          status = 'UNAVAILABLE';
        }
              
        if (status != undefined) {
          logger.info(connection.remoteAddress, 'DOMAINSTATUS', domainname + ':', status, '(from DNS)');
          connection.sendUTF(domainname + ':' + status);
          if (config.memcached) {
            addToMemcache(domainname, status).catch((err) => {
              logger.error('Error when saving result for', domainname + ':', err);
            })
          }
          return;
        }

        anyways(checkWhois(domainname)).then((whoisresult, error) => {
          if (error) {
            logger.error('Whois query error was encountered for', domainname + ':', err);
            status = 'SERVFAIL';
          }
          else {
            if (whoisNotfound(whoisresult)) {
              logger.debug('Domain', domainname, 'is available per whois request.');
              status = 'AVAILABLE';
            }
            else {
              logger.debug('Domain', domainname, 'is not available per whois request.');
              status = 'UNAVAILABLE';
            }
          }

          logger.info(connection.remoteAddress, 'DOMAINSTATUS', domainname + ':', status, '(from WHOIS)');
          connection.sendUTF(domainname + ':' + status);
          if (config.memcached) {
            addToMemcache(domainname, status).catch((err) => {
              logger.error('Error when saving result for', domainname + ':', err);
            })
          }
          return;
        })

      })
    })
  });

  connection.on('close', function(reasonCode, description) {
    logger.info('Client', connection.remoteAddress, 'disconnected.');
  });
});
