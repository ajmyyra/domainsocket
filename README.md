# Domainsocket - Node websocket server for domain lookups

Simple websocket server to make domain lookups. Punycode domains (domains with äöü, asian characters etc) are also supported.

Lookup is first done using C-Ares, and only if no result is found (domain might be available), a more expensice whois request is made to find out the truth.

## Running the server

1) Create a config.js file that has allowed origin listed. For example

```
module.exports = {
    'allowed_origin': 'https://your-web-page.com'
}
```

You might also want to remove all files containing 'debug'. They're useful for debugging, not so much for production.

2) Run server.js under your favorite daemon (m2, forever, plain /usr/bin/node, whatever works for you best)

3) Create a websocket from your website using W3C sockets ( ws = new WebSocket('wss://your-websocket-server-address:8080/', 'echo-protocol'); ) and start using the service. More info at http://codular.com/node-web-sockets .

4) ???

5) PROFIT
