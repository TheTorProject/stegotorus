#!/bin/csh
setenv EVENT_NOKQUEUE yes 
# ./obfsproxy --log-min-severity=debug chop server 87.73.82.145:8080 127.0.0.1:8080 127.0.0.1:8081
# ./obfsproxy --log-min-severity=warn chop server 87.73.82.145:8080 127.0.0.1:8080 127.0.0.1:8081
./obfsproxy --log-min-severity=error chop server 87.73.82.145:8080 127.0.0.1:8080 127.0.0.1:8081

