#!/usr/bin/env bash

# some dependencies for rhel/fedora/centos/sl
[ -e /etc/redhat-release ] && sudo yum install pcre-devel pcre-static gcc make openssl-devel

# create a new dir for the build
BD="build$(date +%s)"
echo working in $BD
mkdir $BD
cd $BD

#-- Build static haproxy
wget http://www.haproxy.org/download/1.5/src/haproxy-1.5.1.tar.gz
tar -xzvf haproxy-1.5.1.tar.gz
cd haproxy-1.5.1
make clean
make TARGET=linux2628 USE_OPENSSL=1
./haproxy -vv

[ $? -lt 1 ] && echo haproxy successfully built at $BD/haproxy-1.5.1/haproxy
