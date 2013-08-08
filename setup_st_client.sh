#!/bin/bash
killall stegotorus

./stegotorus --log-min-severity=debug --timestamp-logs  chop client --trace-packets --disable-retransmit 127.0.0.1:4999 127.0.0.1:5000 http_apache 2> /tmp/client_out.txt
