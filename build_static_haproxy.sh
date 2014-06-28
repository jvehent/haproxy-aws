#!/usr/bin/env bash

# some dependencies for rhel/fedora/centos/sl
[ -e /etc/redhat-release ] && sudo yum install pcre-devel pcre-static gcc make

# create a new dir for the build
BD="build$(date +%s)"
echo working in $BD
mkdir $BD
cd $BD

#-- Build static openssl
wget http://www.openssl.org/source/openssl-1.0.1h.tar.gz
tar -xzvf openssl-1.0.1h.tar.gz
cd openssl-1.0.1h
export STATICLIBSSL="../staticlibssl"
rm -rf "$STATICLIBSSL"
mkdir "$STATICLIBSSL"
make clean
./config --prefix=$STATICLIBSSL no-shared enable-ec_nistp_64_gcc_128
make depend
make
make install_sw

#-- Build static haproxy
cd ..
wget http://haproxy.1wt.eu/download/1.5/src/haproxy-1.5.1.tar.gz
tar -xzvf haproxy-1.5.1.tar.gz
cd haproxy-1.5.1
make clean
make TARGET=linux2628 USE_STATIC_PCRE=1 USE_OPENSSL=1 SSL_INC=$STATICLIBSSL/include SSL_LIB="$STATICLIBSSL/lib -ldl"
./haproxy -vv

[ $? -lt 1 ] && echo haproxy successfully built at $BD/haproxy-1.5.1/haproxy
