# Secure Chat over DIDComm #

Created for [Decentralized Identity Foundation Hackathon](https://difhackathon.devpost.com/).

Just a demo, not even proof-of-concept, let alone working product. Don't use for anything important.

[Apache 2 licensed](LICENSE) so you can exploit the idea and the code however you want.

## Install ## 

```sh
git clone https://github.com/samuelmr/difhack-company.git securechat
cd securechat
npm i
npm -g i @veramo/cli

veramo config create
```

## Configure

Edit the configuration file `agent.yml`. Set the `baseUrl` property in the `constants` section to reflect your host (e.g., `https://chat.example.com`).

I run Apache as an SSL proxy in front of the application. Apache routes all requests to the `chat` host to the port configured in `agent.yml`:

```apacheconf
<IfModule mod_rewrite.c>
    RewriteEngine On
    ProxyPreserveHost on
    RewriteCond   %{SERVER_NAME}      ^(chat.+)
    RewriteRule   ^(.*)/ws$           ws://localhost:3332$1 [P,END]
    RewriteCond   %{SERVER_NAME}      ^(chat.+)
    RewriteRule   ^(.*)$              http://localhost:3332$1 [P,E=Host:%1]
    Header        set   Host          %{Host}e
</IfModule>
```
[Express](https://expressjs.com/) is serving both HTTP and WebSocket services in the same port.

## Run

I use [PM2](https://pm2.keymetrics.io/) to keep the service running.

```sh
pm2 install --name "Secure chat" index.js
```