#!/bin/bash

ODIR=~/src/DEFIANCE/stegotorus

################################################################################
# helper functions:

usage () {
if [ $# -gt 0 ]; then
    echo " *** ERROR: $1"
fi
cat << EOF

usage: $0 <OPTIONS> [server|client] [install-dir]

Start obfsproxy server or client with given options. If the optional install-dir
is given, override the value set in the script.

OPTIONS:
   -h             Show this message
   -i <addr>      IP address (default: 127.0.0.1)
   -p <n>         port number (default: 8080)
   -l <severity>  Log severity: warn, error, debug (default: error)
   -b <host>      Host name (or IP address) of Tor Bridge
                  with port number attached via ':' or omitted
                  (default: 87.73.82.145:8080)
   -n <n>         Multiply the number of IP addresses on the client
EOF
}

################################################################################
# parse command line:

# default values:
IP=127.0.0.1
PORT=8080
N=1
LOG=error
BRIDGE_IP=87.73.82.145
BRIDGE_PORT=8080
while getopts "hi:p:l:b:n:" OPTION
do
    case $OPTION in
        h|\?)
            usage; exit 1
            ;;
        i)
            IP=$OPTARG
            ;;
        p)
            PORT=$OPTARG
            ;;
	n)
	    N=$OPTARG
	    ;;
	l)
	    LOG=`echo $OPTARG | tr '[A-Z]' '[a-z]'`  # make lower case
	    ;;
	b)
	    arr=(${OPTARG//:/ })
	    BRIDGE_IP=${arr[0]}
	    if [ ${#arr[@]} -gt 1 ]; then
		BRIDGE_PORT=${arr[1]}
	    fi
	    ;;
    esac
    shift $((OPTIND-1)); OPTIND=1 
done

# test if $LOG is valid
case $LOG in
    debug|warn|error)
	;;
    *) 
	usage "Unknown log level given: $LOG"; exit 1
	;;
esac

# now $@ has remaining arguments:
if [ $# -lt 1 ]; then
    usage "need 'server' or 'client' as argument"; exit 1
fi
TYPE=`echo $1 | tr '[A-Z]' '[a-z]'`  # turn argument into lower case
case $TYPE in
    server|client)
	;;
    *)
	usage "argument $1 not recognized"; exit 1
	;;
esac

# check optional install location given as an argument
if [ $# -gt 1 ]; then
    if [[ ! -d $2 ]]; then
	usage "argument $2 is not a directory"; exit 1
    fi
    if [[ ! -x $2/obfsproxy ]]; then
	usage "directory $2 does not contain executable of 'obfsproxy'"; exit 1
    fi
    ODIR=$2
fi

################################################################################
# start obfsproxy

echo "Using obfsproxy in \"$ODIR\""
cd $ODIR
export EVENT_NOKQUEUE=yes
case $TYPE in
    server)
	./obfsproxy --log-min-severity=$LOG chop server $BRIDGE_IP:$BRIDGE_PORT $IP:$PORT
	;;
    client)
	IPS=""
	for (( c=1; c<=$N; c++)) ; do 
	    IPS="${IPS}${IP}:${PORT} x_http2 " ;
	done
	./obfsproxy --log-min-severity=$LOG chop socks 127.0.0.1:1080 $IPS
	;;
esac
