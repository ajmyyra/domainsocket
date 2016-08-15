# Domainsocket - Node websocket server for domain lookups

Simple websocket server to make domain lookups. Punycode domains (domains with äöü, asian characters etc) are also supported.

Lookup is first done using C-Ares, and only if no result is found (domain might be available), a more expensive whois request is made to find out the truth.

TODO: Secure it, http://www.giacomovacca.com/2015/02/websockets-over-nodejs-from-plain-to.html

## Running the server

1) Clone the repository to your server and run 'npm install' in the directory.

2) Create a config.js file that has allowed origin and if needed, SSL support enabled.

With SSL:
```
module.exports = {
    'allowed_origin': 'https://your-web-page.com',
    'ssl': true,
    'ssl_key': '/path/to/your/ssl.key',
    'ssl_cert': '/path/to/your/ssl.crt'
}
```

Without SSL:
```
module.exports = {
    'allowed_origin': 'https://your-web-page.com',
    'ssl': false
}
```

3) Run server.js under your favorite daemon (m2, forever, plain /usr/bin/node, whatever works for you best)

4) Create a websocket from your website using W3C sockets ( ws = new WebSocket('wss://your-websocket-server-address:8080/', 'echo-protocol'); ) and start using the service. More info at http://codular.com/node-web-sockets .

