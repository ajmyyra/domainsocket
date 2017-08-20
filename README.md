# Domainsocket - Node websocket server for domain lookups

Simple websocket server to make domain lookups. Punycode domains (domains with äöü, asian characters etc) are also supported.

Lookup is first done using C-Ares DNS library, and only if no result is found (domain might be available), a more expensive whois request is made to find out the truth.

Results can be saved into Memcached, so they don't need to be constantly re-fetched.

## Running the server

1) Clone the repository to your server and run 'npm install' in the directory.

2) Create a config.js file that has allowed origin, memcached and SSL information. Debug mode is a lot more verbose, causing too much logging in production. Config variables serverip and serverport can be left blank and defaults will then be used (0.0.0.0:8080).

With SSL and memcached, but without debug (standard production config):
```
module.exports = {
    'debug': false,
    'allowed_origin': [ 'https://your-web-page.com', 'https://sub.your-web-page.com' ],
    'memcached': true,
    'memcached_server': '127.0.0.1:11211',
    'ssl': true,
    'ssl_key': '/path/to/your/ssl.key',
    'ssl_cert': '/path/to/your/ssl.crt'
}
```

Without SSL and memcached, but with debug on (common development setup):
```
module.exports = {
    'serverip': '127.0.0.1',
    'serverport': '8000',
    'allowed_origin': [ 'http://localhost:8000' ],
    'memcached': false,
    'ssl': false,
    'debug': true
}
```

3) Run server.js under your favorite daemon (m2, forever, systemd service or just plain /usr/bin/node, whatever works for you best)

4) Create a websocket from your website using W3C sockets and echo-protocol ( ws = new WebSocket('wss://your-websocket-server-address:8080/', 'echo-protocol'); ) and start using the service. More info at http://codular.com/node-web-sockets for an easy client setup.

