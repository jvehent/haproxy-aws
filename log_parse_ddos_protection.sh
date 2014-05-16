#!/usr/bin/env bash
if [[ ! -n $1 || ! -n $2 || ! -n $3 ]]
then
	echo
	echo "$0 <IP address> <start date> <stop date>"
	echo "parse haproxy logs to count success and failures per seconds"
	echo "between two time periods"
	echo 
	echo "example: $0 88.191.125.180 'Fri Jan 17 17:30:00 UTC 2014' 'Fri Jan 17 17:40:00 UTC 2014'"
	echo
	exit 1
fi
OIFS=$IFS
IFS=$'\n'
SRCIP=$1
STARTTS=$(date -d "$2" +%s)
if [ $? -gt 0 ]; then echo "invalid date $2"; exit 1;fi
STOPTS=$(date -d "$3" +%s)
if [ $? -gt 0 ]; then echo "invalid date $3"; exit 1;fi
TS=$STARTTS
while [ $TS -le $STOPTS ]
do
	cts=$(date -d"@$TS" +%d/%b/%Y:%H:%M:%S)
	ctr_success=0
	ctr_failure=0
	for line in $(grep "$cts" /var/log/messages|grep "$SRCIP"|grep "haproxy")
	do
		# status code is at col 11
		st=$(echo $line|awk '{print $11}')
		if [ $st -lt 0 ]
		then
			ctr_failure=$((ctr_failure + 1))
		else
			ctr_success=$((ctr_success + 1))
		fi
	done
	echo $cts $ctr_success $ctr_failure
	# go to next second
	TS=$((TS + 1 ))
done
IFS=$OIFS
