#!/bin/csh
# ./obfsproxy --log-min-severity=debug x_dsteg socks 127.0.0.1:1080 x_http

setenv EVENT_NOKQUEUE yes 
./obfsproxy --log-min-severity=debug chop socks 127.0.0.1:1080 127.0.0.1:8080 x_http2 127.0.0.1:8081 x_http2
# ./obfsproxy --log-min-severity=warn chop socks 127.0.0.1:1080 127.0.0.1:8080 x_http2 127.0.0.1:8081 x_http2
#./obfsproxy --log-min-severity=error chop socks 127.0.0.1:1080 127.0.0.1:8080 x_http2 127.0.0.1:8081 x_http2

