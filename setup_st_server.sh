#!/bin/bash
killall stegotorus

./stegotorus --log-min-severity=debug --timestamp-logs chop server --trace-packets --disable-retransmit 127.0.0.1:5001 127.0.0.1:5000 $1 2> /tmp/server_out.txt&
