# Secure Chat over DIDComm #

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
## Run

I use [PM2](https://pm2.keymetrics.io/) to keep the service running.

```sh
pm2 install --name "Secure chat" index.js
```