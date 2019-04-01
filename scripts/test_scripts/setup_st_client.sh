#!/bin/bash
#killall stegotorus

#http and only js
./stegotorus --log-min-severity=debug --timestamp-logs  chop client --trace-packets --disable-retransmit 127.0.0.1:4999 http 127.0.0.1:5000 --steg-mod js #2> /tmp/client_out.txt

#./stegotorus --log-min-severity=debug --timestamp-logs  chop client --trace-packets --disable-retransmit 127.0.0.1:4999 http_apache 127.0.0.1:5000 #2> /tmp/client_out.txt
