#!/bin/bash
killall stegotorus

./stegotorus --log-min-severity=debug --timestamp-logs chop server --trace-packets --disable-retransmit 127.0.0.1:5001 http $1 127.0.0.1:5000 --steg-mod js #2> /tmp/server_out.txt&

#http_apache
#./stegotorus --log-min-severity=debug --timestamp-logs chop server --trace-packets --disable-retransmit --minimum-noise-to-signal 0 --cover-server 108.174.48.210 --cover-list apache_payload/equalitie_items.cvs 127.0.0.1:5001 127.0.0.1:5000 $1 #2> ~/tmp/server_out.txt&

#mit.edu: 23.42.70.151
#--cover-server 151.236.219.59:80 --cover-list apache_payload/bbc_items_5000.csv
#ssh -ND 5001 vmon@localhost

#./stegotorus chop server --disable-retransmit 127.0.0.1:5001 194.14.179.176:5000 http
