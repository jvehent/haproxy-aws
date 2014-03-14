# To Build:
#
# sudo yum -y install rpmdevtools && rpmdev-setuptree
# sudo yum -y install pcre-devel openssl-devel
# wget https://raw.github.com/nmilford/rpm-haproxy/master/haproxy.spec -O ./rpmbuild/SPECS/haproxy.spec
# wget http://haproxy.1wt.eu/download/1.5/src/devel/haproxy-1.5-dev22.tar.gz -O ./rpmbuild/SOURCES/haproxy-1.5-dev22.tar.gz
# rpmbuild -bb  ./rpmbuild/SPECS/haproxy.spec

%define version 1.5
%define dev_rel dev22
%define release 1

Summary: HA-Proxy is a TCP/HTTP reverse proxy for high availability environments
Name: haproxy
Version: %{version}
Release: %{dev_rel}.%{release}
License: GPL
Group: System Environment/Daemons
URL: http://haproxy.1wt.eu
Source0: http://haproxy.1wt.eu/download/1.5/src/devel/%{name}-%{version}-%{dev_rel}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: pcre-devel openssl-devel
Requires: /sbin/chkconfig, /sbin/service

%description
HAProxy is a TCP/HTTP reverse proxy which is particularly suited for high
availability environments. Indeed, it can:
- route HTTP requests depending on statically assigned cookies
- spread the load among several servers while assuring server persistence
  through the use of HTTP cookies
- switch to backup servers in the event a main one fails
- accept connections to special ports dedicated to service monitoring
- stop accepting connections without breaking existing ones
- add/modify/delete HTTP headers both ways
- block requests matching a particular pattern

It needs very little resource. Its event-driven architecture allows it to easily
handle thousands of simultaneous connections on hundreds of instances without
risking the system's stability.

%prep
%setup -n %{name}-%{version}-%{dev_rel}

# We don't want any perl dependecies in this RPM:
%define __perl_requires /bin/true

%build
%{__make} USE_PCRE=1 TARGET=linux2628 USE_OPENSSL=1

%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%{__install} -d %{buildroot}%{_sbindir}
%{__install} -d %{buildroot}%{_sysconfdir}/rc.d/init.d
%{__install} -d %{buildroot}%{_sysconfdir}/%{name}
%{__install} -d %{buildroot}%{_mandir}/man1/

%{__install} -s %{name} %{buildroot}%{_sbindir}/
%{__install} -c -m 644 examples/%{name}.cfg %{buildroot}%{_sysconfdir}/%{name}/
%{__install} -c -m 755 examples/%{name}.init %{buildroot}%{_sysconfdir}/rc.d/init.d/%{name}
%{__install} -c -m 755 doc/%{name}.1 %{buildroot}%{_mandir}/man1/

%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
  /sbin/service %{name} stop >/dev/null 2>&1 || :
  /sbin/chkconfig --del %{name}
fi

%postun
if [ "$1" -ge "1" ]; then
  /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root)
%doc CHANGELOG TODO examples/*.cfg doc/haproxy-en.txt doc/haproxy-fr.txt doc/architecture.txt doc/configuration.txt
%doc %{_mandir}/man1/%{name}.1*

%attr(0755,root,root) %{_sbindir}/%{name}
%dir %{_sysconfdir}/%{name}
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.cfg
%attr(0755,root,root) %config %{_sysconfdir}/rc.d/init.d/%{name}

%changelog
* Fri Mar 14 2014 Julien Vehent <jvehent@mozilla.com>
- Build RPM on 1.5-dev22. see changelog at http://haproxy.1wt.eu/git?p=haproxy.git;a=log
