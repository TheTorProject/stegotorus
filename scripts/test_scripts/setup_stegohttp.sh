#!/bin/bash
killall stegotorus

./stegotorus --log-min-severity=debug --timestamp-logs chop server --trace-packets --disable-retransmit 127.0.0.1:5001 127.0.0.1:5000 http 2> tmp/server_out.txt&

./stegotorus --log-min-severity=debug --timestamp-logs  chop client --trace-packets --disable-retransmit 127.0.0.1:4999 127.0.0.1:5000 http 2> tmp/client_out.txt&

ssh -ND 5001 vmon@localhost

