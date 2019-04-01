#!/bin/bash
killall stegotorus

./stegotorus chop server --disable-retransmit 127.0.0.1:5001 127.0.0.1:5000 $1 &

./stegotorus chop client --disable-retransmit 127.0.0.1:4999 127.0.0.1:5000 $1 &

ssh -ND 5001 vmon@localhost

