# moproxy

*moproxy* is a high performance SOCKS5 (RFC1928) and HTTP proxy server written in Golang.
It uses *[tcpserver](https://github.com/maurice2k/tcpserver)* as a basis.


**THIS CODE IS NOT YET PRODUCTION READY.** As always, use at your own risk :) 

## Features
* IPv4 and IPv6 support (also IPv4 to IPv6 and vice versa)
* Access rules (from/to IP ranges)
* Support for username/password authentication
* Timeouts for various stages
* CONNECT command (normal SOCKS5 proxy usage)
* BIND command (required for i.e. non-PASV FTP)
* TCP FastOpen (TFO) support for remote connections with Linux Kernel 4.11+
* Config reloading (using SIGHUP)


## Installation

Installing moproxy is pretty simple using `make`. It only requires Go 1.13 (or better) to be installed on your system. 
```
# make
# make install
```

This builds and installs moproxy to `/opt/moproxy` by default and registers a systemd service with the name `moproxy`to `start`, `reload` and `stop` the service.

You need to copy `moproxy.conf.dist` to `moproxy.conf` within `/opt/moproxy/configs` and adjust it to your needs prior to starting the service.
The config file is in JSON format with documentation and examples as comments.



## TODOs
* Logging to SQLite
* JSON status page
* Support for more flexible authenticators (squid style)


## License
*moproxy* is available under the MIT [license](LICENSE).
