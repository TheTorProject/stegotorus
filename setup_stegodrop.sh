#!/bin/bash
killall stegotorus
killall tester_proxy
echo $1
echo $2

./stegotorus --log-min-severity=debug --timestamp-logs chop server --trace-packets 127.0.0.1:5001 127.0.0.1:5002 $1 2> tmp/server_out.txt&

./stegotorus --log-min-severity=debug --timestamp-logs  chop client --trace-packets 127.0.0.1:4999 127.0.0.1:5000 $1 2> tmp/client_out.txt&

./tester_proxy --drop-rate $2 127.0.0.1:5000 127.0.0.1:5002 2>tmp/proxy_out.txt&

ssh -ND 5001 vmon@localhost

