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

## TODOs
* Cleanup HTTP non-CONNECT part (maybe remove usage of http.Request/http.Response)
* Logging to SQLite
* JSON status page
* Support for more flexible authenticators (squid style)
* Maybe support UDP ASSOCIATE command


## License
*moproxy* is available under the MIT [license](LICENSE).
