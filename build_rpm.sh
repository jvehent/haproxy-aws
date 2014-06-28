#!/usr/bin/env bash

haproxyversion="1.5.1"

echo Installing dependencies
sudo yum -y install rpmdevtools pcre-devel openssl-devel gcc make

echo Backup up previous build dir
[ -e ~/rpmbuild ] && mv ~/rpmbuild rpmbuild-$(date +%s)

echo Initializing build dir
rpmdev-setuptree

echo Download HAProxy source
wget http://haproxy.1wt.eu/download/1.5/src/haproxy-$haproxyversion.tar.gz -O ~/rpmbuild/SOURCES/haproxy-$haproxyversion.tar.gz

echo Copying SPEC file over to build dir
cp haproxy.spec ~/rpmbuild/SPECS/

echo Building RPM
rpmbuild -bb ~/rpmbuild/SPECS/haproxy.spec

echo Moving RPMs to local dir
find ~/rpmbuild/RPMS/ -type f -name *.rpm -exec cp {} . \;

echo Backing up build dir
mv ~/rpmbuild rpmbuild-$(date +%s)
