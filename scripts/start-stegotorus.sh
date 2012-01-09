#!/bin/bash

################################################################################
# variables with default values
declare IP=127.0.0.1
declare -i PORT=8080
declare -i N=1
declare LOG=info
declare BRIDGE_IP=87.73.82.145
declare -i BRIDGE_PORT=8080

################################################################################
# helper functions:

usage () {
if [ $# -gt 0 ]; then
    echo " *** ERROR: $1"
fi
cat << EOF

usage: $0 <OPTIONS> [server|client] [install-dir]

Start StegoTorus server or client from given installation directory with given options.

OPTIONS:
   -h             Show this message
   -i <addr>      IP address (default: ${IP})
   -p <n>         port number (default: ${PORT})
   -l <severity>  Log severity: warn, error, info, debug (default: ${LOG})
   -b <host>      Host name (or IP address) of Tor Bridge
                  with port number attached via ':' or omitted
                  (default: ${BRIDGE_IP}:${BRIDGE_PORT})
   -n <n>         Multiply the number of IP addresses on the client (default: ${N})
EOF
}

################################################################################
# parse command line:

# default values:
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
if [ $# -lt 2 ]; then
    usage "need stegotorus installation directory as argument"; exit 1
fi
ODIR=$2
if [[ ! -d $ODIR ]]; then
    usage "$ODIR is not a directory"; exit 1
fi
if [[ ! -x $ODIR/stegotorus ]]; then
    usage "directory $ODIR does not contain executable of 'stegotorus'"; exit 1
fi

################################################################################
# start stegotorus

echo "Using stegotorus in \"$ODIR\""
cd $ODIR
export EVENT_NOKQUEUE=yes
case $TYPE in
    server)
	./stegotorus --log-min-severity=$LOG chop server $BRIDGE_IP:$BRIDGE_PORT $IP:$PORT
	;;
    client)
	IPS=""
	for (( c=1; c<=$N; c++)) ; do 
	    IPS="${IPS}${IP}:${PORT} http " ;
	done
	./stegotorus --log-min-severity=$LOG chop socks 127.0.0.1:1080 $IPS
	;;
esac
