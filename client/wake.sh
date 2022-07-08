#!/bin/bash

WAKEHOST=i4woke.informatik.uni-erlangen.de
WAKEPORT=8423
WAKETIME=5

echo "i4 Wake-On-LAN Client"
if [[ $# -eq 0 ]] ; then
	echo "Usage $0 HOST [HOST...]" >&2
	exit 1
else
	for HOST in $@ ; do
		if result=$(echo "${HOST}" | nc -w${WAKETIME} ${WAKEHOST} ${WAKEPORT} 2>/dev/null) ; then
			printf " - %-20s [%s]\n" "${HOST}" "${result}"
		else
			echo "Connection to i4 Wake-On-LAN Server at ${WAKEHOST}:${WAKEPORT} failed - abort!"
			exit 1
		fi
	done
fi
