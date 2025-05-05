# 🌱 tiny-tls
This project implements a minimum TLS1.3 server for educational use.

* Written in only standard libraries, no 3rd party libs
* Minimum features to show a small web page
* Not for production use

## Getting started
At server-side, run these:

```
$ git clone https://github.com/asmsuechan/tiny-tls
$ cd tiny-tls
$ npm i
$ npm run build && node lib/index.js
```

At client, access `https://localhost` or run these:

```
$ openssl s_client -connect localhost:443 -tls1_3 -debug -msg -security_debug_verbose -trace
```