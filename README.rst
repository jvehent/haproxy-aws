==============================================
HAProxy termination in AWS: technical overview
==============================================

.. |date| date::
.. |time| date:: %H:%M

:Revision: Last updated on |date| at |time|.
:Author: Julien Vehent <julien@linuxwall.info>

.. sectnum::

.. contents:: Table of Contents

This document explains how HAProxy and Elastic Load Balancer can be used in
Amazon Web Services to provide performant and secure HTTPS termination. The goal
is to provide the following features:

* DDoS Protection: we use HAProxy to mitigate low to medium DDoS attacks, with
  sane limits and custom blacklist.

* Application firewall:  we perform a first level of filtering in HAProxy, that
  protects NodeJS against all sorts of attack, known and to come. This will be done
  by inserting a set of regexes in HAProxy ACLs, that get updated when the
  application routes are updated. Note that managing these ACLs will not impact
  uptime, or require redeployment.

* SSL/TLS: ELBs support the PROXY protocol, and so does HAProxy, which allows us
  to proxy the tcp connection to HAProxy. It gives us better TLS, backed by
  OpenSSL, at the cost of managing the TLS keys on the HAProxy instances.

* Logging: ELBs have no support for logging. HAProxy, however, has excellent
  logging for TCP, SSL and HTTPS. We leverage the flexibility of HAProxy's logging
  to improve our DDoS detection capabilities. We also want to uniquely identify
  requests in HAProxy and NodeJS, and correlate events, using a `unique-id`.

Below is our target setup:

.. image:: haproxy-aws-arch-diagram.png
   :alt: architecture diagram

Building process
----------------
The following script builds haproxy with statically linked OpenSSL and PCRE
support.

.. include:: build_static_haproxy.sh
	:code: bash

PROXY protocol between ELB and HAProxy
--------------------------------------

This configuration uses an Elastic Load Balancer in TCP mode, with PROXY
protocol enabled. The PROXY protocol adds a string at the beginning of the TCP
payload that is passed to the backend. This string contains the IP of the client
that connected to the ELB, which allows HAProxy to feed its internal state with
this information, and act as if it had a direct TCP connection to the client.

For more information on the PROXY protocol, see
http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt

First, we need to create an ELB, and enable a TCP listener on port 443 that
supports the PROXY protocol. The ELB will not decipher the SSL, but instead pass
the entire TCP payload down to Haproxy.

ELB Configuration
~~~~~~~~~~~~~~~~~
PROXY protocol support must be enabled on the ELB.

.. code:: bash

	$ ./elb-describe-lb-policy-types -I AKIA... -S Ww1... --region us-east-1
	POLICY_TYPE  ProxyProtocolPolicyType	Policy that controls whether to include the
											IP address and port of the originating request
											for TCP messages. This policy operates on
											TCP/SSL listeners only
	.....

The policy name we want to enable is `ProxyProtocolPolicyType`. We need the load
balancer name for that, and the following command:

.. code:: bash

	$ ./elb-create-lb-policy elb123-testproxyprotocol \
	--policy-name EnableProxyProtocol \
	--policy-type ProxyProtocolPolicyType \
	--attribute "name=ProxyProtocol, value=true" \
	-I AKIA... -S Ww1... --region us-east-1

	OK-Creating LoadBalancer Policy


	$ ./elb-set-lb-policies-for-backend-server elb123-testproxyprotocol \
	--policy-names EnableProxyProtocol \
	--instance-port 443 \
	-I AKIA... -S Ww1... --region us-east-1

	OK-Setting Policies

Now configure a listener on TCP/443 on that ELB, that points to TCP/443 on the
HAProxy instance. On the instance side, make sure that your security group
accepts traffic from the ELB security group on port 443.

HAProxy frontend
~~~~~~~~~~~~~~~~

The HAProxy frontend listens on port 443 with a SSL configuration, as follow:

.. code:: bash

	frontend https
		bind 0.0.0.0:443 accept-proxy ssl ......

Note the `accept-proxy` parameter of the bind command. This option tells HAProxy
that whatever sits in front of it will append the PROXY header to TCP payloads.
The rest of the SSL configuration isn't covered here, but in the HAProxy SSL
section.

Healthchecks between ELB and HAProxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As of writing of this document, it appears that ELBs do not use the proxy
protocol when running healthchecks against an instance. As a result, these
healthchecks cannot be handled by the `https frontend`, because HAProxy will
fail when looking for a PROXY header that isn't there.

The workaround is to create a secondary `frontend` in HAProxy that is entirely
dedicated to answering healthchecks from the ELB.

The configuration below uses the `monitor` option to check the health of the
nodejs backend. If more than one server is alive in that backend, then our
`health` frontend will return `200 OK`. If no server is alive, a `503` will be
returned. All the ELB has to do is to query the URL at
http://haproxy_host:34180/haproxy_status . To reduce the overhead, we also
disable SSL on the health frontend.

.. code:: bash

	# frontend used to return health status without requiring SSL
	frontend health
		bind 0.0.0.0:34180	# 34180 means EALTH ;)
		# create a status URI in /haproxy_status that will return
		# a 200 is backend is healthy, and 503 if it isn't. This
		# URI is queried by the ELB.
		acl backend_dead nbsrv(nodejs) lt 1
		monitor-uri /haproxy_status
		monitor fail if backend_dead

ELB Logging
-----------
TODO

HAProxy Logging
---------------

HAProxy supports custom log format, which we want here, as opposed to default
log format, in order to capture TCP, SSL and HTTP information on a single line.

For our logging, we want the following:

1. TCP/IP logs first, such that these are always present, even if HAProxy cuts
   the connection before processing the SSL or HTTP traffic
2. SSL information
3. HTTP information

.. code:: bash

	log-format [%pid]\ [%Ts.%ms]\ %ac/%fc/%bc/%bq/%sc/%sq/%rc\ %Tq/%Tw/%Tc/%Tr/%Tt\
	%tsc\ %ci:%cp\ %fi:%fp\ %si:%sp\ %ft\ %sslc\ %sslv\ %{+Q}r\ %ST\ %b:%s\ %ID\
	%{+Q}CC\ %{+Q}hr\ %{+Q}CS\ %{+Q}hs\ %B\ bytes

The format above will generate:

 ::

	Mar  7 14:18:50 localhost haproxy[10282]: [10282] [1394201930.258] 1/1/0/0/1/0/0 91/0/0/3/95 ---- 2.1.17.87:52354 10.151.122.228:443 127.0.0.1:8000 fxa-https~ ECDHE-RSA-AES128-SHA TLSv1.2 "GET / HTTP/1.1" 200 fxa-nodejs:nodejs1 485B7525:CC82_0A977AE4:01BB_5319D54A_0004:282A - {|Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/} - - 705 bytes

The log-format contains very detailed information on the connection itself, but
also on the state of haproxy itself. Below is a description of the fields we
used in our custom log format.

* `%pid`: process ID of HAProxy
* `%Ts.%ms`: unix timestamp + milliseconds
* `%ac`: total number of concurrent connections
* `%fc`: total number of concurrent connections on the frontend
* `%bc`: total number of concurrent connections on the backend
* `%bq`: queue size of the backend
* `%sc`: total number of concurrent connections on the server
* `%sq`: queue size of the server
* `%rc`: connection retries to the server
* `%Tq`: total time to get the client request (HTTP mode only)
* `%Tw`: total time spent in the queues waiting for a connection slot
* `%Tc`: total time to establish the TCP connection to the server
* `%Tr`: server response time (HTTP mode only)
* `%Tt`: total session duration time, between the moment the proxy accepted it
  and the moment both ends were closed.
* `%tsc`: termination state (see `8.5. Session state at disconnection`)
* `%ci:%cp`: client IP and Port
* `%fi:%fp`: frontend IP and Port
* `%si:%sp`: server IP and Port
* `%ft`: transport type of the frontend (with a ~ suffix for SSL)
* `%sslc %sslv`: SSL cipher and version
* `%{+Q}r`: HTTP request, between double quotes
* `%ST`: HTTP status code
* `%b:%s`: backend name and server name
* `%ID`: Unique ID generated for each request
* `%CC`: captured request cookies
* `%hr`: captured request headers
* `%CS`: captured response cookies
* `%hs`: captured response headers
* `%B`: bytes read from server to client (response size)

For more details on the available logging variables, see the HAProxy
configuration, under `8.2.4. Custom log format`.
http://haproxy.1wt.eu/download/1.5/doc/configuration.txt

Unique request ID
~~~~~~~~~~~~~~~~~

Tracking requests across multiple servers can be problematic, because the chain
of events triggered by a request on the frontend are not tied to each other.
HAProxy has a simple mechanism to insert a unique identifier to incoming
requests, in the form of an ID inserted in the request headers, and passed to
the backend server. This ID can then be logged by the backend server, and passed
on to the next step. In a largely distributed environment, the unique ID makes
tracking requests propagation a lot easier.

The unique ID is declared on the HTTPS frontend as follow:

.. code:: bash

	# Insert a unique request identifier is the headers of the request
	# passed to the backend
	unique-id-format %{+X}o\ %ci:%cp_%fi:%fp_%Ts_%rt:%pid
	unique-id-header X-Unique-ID

This will add an ID that is composed of hexadecimal variables, taken from the
client IP and port, frontend IP and port, timestamp, request counter and PID.
An example of generated ID is **485B7525:CB2F_0A977AE4:01BB_5319CB0C_000D:27C0**.

The Unique ID is logged and added to the request headers passed to the backend
in the `X-Unique-ID` header.

 ::

	GET / HTTP/1.1
	Host: backendserver123.example.net
	User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/25.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate
	DNT: 1
	Cache-Control: max-age=0
	X-Unique-ID: 485B7525:CB70_0A977AE4:01BB_5319CD3F_0163:27C0
	X-Forwarded-For: 2.12.17.87

Capturing headers and cookies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In the log format, we defined fields for the request and response headers and
cookies. But, by default, this fields will show empty in the logs. In order to
log headers and cookies, special `capture` parameters must be set in the
frontend.

Here's how we can capture the user-agent and referrer sent by the client in the
HTTP request.

.. code:: bash

	capture request header Referrer len 64
	capture request header User-Agent len 64

Cookies can be captures the same way:

.. code:: bash

	capture cookie mycookie123=  len 32

Rate limiting & DDoS protection
-------------------------------

Automated mode
~~~~~~~~~~~~~~

Blacklists & Whitelists
~~~~~~~~~~~~~~~~~~~~~~~

URL filtering with ACLs
-----------------------

HAProxy management
------------------

Stat socket
~~~~~~~~~~~

Soft reload
~~~~~~~~~~~
HAProxy supports soft configuration reload, that doesn't drop connections. To
perform a soft reload, call haproxy with the following command:

.. code:: bash

	$ sudo /opt/haproxy -f /etc/haproxy/haproxy.cfg -sf $(pidof haproxy)

The old process will be replaced with a new one, that uses a fresh
configuration. The logs will show the reload:

 ::

	Mar  6 12:59:41 localhost haproxy[7603]: Proxy https started.
	Mar  6 12:59:41 localhost haproxy[7603]: Proxy app started.
	Mar  6 12:59:41 localhost haproxy[5763]: Stopping frontend https in 0 ms.
	Mar  6 12:59:41 localhost haproxy[5763]: Stopping backend app in 0 ms.
	Mar  6 12:59:41 localhost haproxy[5763]: Proxy https stopped (FE: 29476 conns, BE: 0 conns).
	Mar  6 12:59:41 localhost haproxy[5763]: Proxy app stopped (FE: 0 conns, BE: 1746 conns).

Full HAProxy configuration
--------------------------

.. include :: haproxy.cfg
   :code: bash


