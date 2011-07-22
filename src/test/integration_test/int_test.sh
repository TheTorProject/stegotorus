#!/bin/bash

# replace this with your path to obfsproxy.
OBFSPROXY="../../../obfsproxy"
# replace this with your path to ncat.
NCAT=ncat

ENTRY_PORT=4999
SERVER_PORT=5000
NCAT_PORT=5001

DIR=inttemp_temp
FILE1=$DIR/test1
FILE2=$DIR/test2

mkdir -p $DIR ; :>$FILE1

# TEST 1
# We open a server and a client and transfer a file. Then we check if the output of the
# server is the same as the file we sent.

$NCAT -k -l -o $FILE1 -p $NCAT_PORT > /dev/null &
ncat1_pid=$!


$OBFSPROXY --log-min-severity=warn obfs2 --dest=127.0.0.1:$NCAT_PORT server 127.0.0.1:$SERVER_PORT \
    + obfs2 --dest=127.0.0.1:$SERVER_PORT client 127.0.0.1:$ENTRY_PORT &
obfsproxy_pid=$!
sleep 1


$NCAT localhost $ENTRY_PORT < alpha &
ncat2_pid=$!
sleep 2

if cmp -s alpha $FILE1
then echo "GREAT SUCCESS 1!" ; rm $FILE1
else echo "GREAT FAIL 1!"
fi

kill -9 $ncat1_pid
kill -9 $obfsproxy_pid
kill -9 $ncat2_pid

sleep 2

# TEST 2
# We open an obfsproxy SOCKS server on the dummy protocol and an ncat listening.
# Then we configure another ncat to use SOCKS4 and transfer a file to the other ncat.
# Finally, we check if the file was sent correctly.

:>$FILE2

$NCAT -k -l -o $FILE2 -p $NCAT_PORT > /dev/null &
ncat1_pid=$!

$OBFSPROXY --log-min-severity=warn dummy socks 127.0.0.1:$SERVER_PORT &
obfsproxy_pid=$!
sleep 1

$NCAT --proxy-type socks4 --proxy 127.0.0.1:$SERVER_PORT \
    127.0.0.1 $NCAT_PORT < alpha &
ncat2_pid=$!
sleep 2

if cmp -s alpha $FILE2
then echo "GREAT SUCCESS 2!" ; rm $FILE2
else echo "GREAT FAIL 2!"
fi

kill -9 $ncat1_pid
kill -9 $obfsproxy_pid
kill -9 $ncat2_pid

rmdir $DIR

