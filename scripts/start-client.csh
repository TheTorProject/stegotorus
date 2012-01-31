#!/bin/csh
# ./stegotorus --log-min-severity=debug x_dsteg socks 127.0.0.1:1080 x_http

setenv EVENT_NOKQUEUE yes
#./stegotorus --log-min-severity=debug chop socks 127.0.0.1:1080 127.0.0.1:8080 http 127.0.0.1:8081 http
# ./stegotorus --log-min-severity=warn chop socks 127.0.0.1:1080 127.0.0.1:8080 http 127.0.0.1:8081 http
#./stegotorus --log-min-severity=error chop socks 127.0.0.1:1080 127.0.0.1:8080 http 127.0.0.1:8081 http
./stegotorus --log-min-severity=error chop socks 127.0.0.1:1080 127.0.0.1:3333 dummy
# 127.0.0.1:3333 dummy

