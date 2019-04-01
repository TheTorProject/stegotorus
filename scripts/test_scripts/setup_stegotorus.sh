#!/bin/bash
killall stegotorus

./stegotorus --log-min-severity=debug --timestamp-logs chop server --trace-packets --disable-retransmit --minimum-noise-to-signal 0 127.0.0.1:5001 127.0.0.1:5000 $1 2> /tmp/server_out.txt&

./stegotorus --log-min-severity=debug --timestamp-logs  chop client --trace-packets --disable-retransmit --minimum-noise-to-signal 0 127.0.0.1:4999 127.0.0.1:5000 $1 2> /tmp/client_out.txt&

#--cover-server 151.236.219.59:80 --cover-list apache_payload/bbc_items_5000.csv
#ssh -ND 5001 vmon@localhost
