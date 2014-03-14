=========================================
Guidelines for HAProxy termination in AWS
=========================================

.. title:: Guidelines for HAProxy termination in AWS
.. |gentime| date:: %F %H:%M %Z
.. role:: lvl_low
	:class: st_gray
.. role:: lvl_medium
	:class: st_blue
.. role:: lvl_high
	:class: st_yellow
.. role:: lvl_max
	:class: st_red
.. role:: ready
	:class: st_green
.. role:: not_ready
	:class: st_red
.. |br| raw:: html

	<br />

.. sidebar:: Document status

           +-----------------------+------------------------------------------------------+
           |:not_ready:`NOT READY` | $Revision:        $ @ |gentime|                      |
           +===============+=======+=============+=======================+================+
           |**Author**     |Julien Vehent        |**Review**             | CloudOps       |
           +---------------+---------------------+-----------------------+----------------+

    .. sectnum::

    .. contents:: **Table of contents**
               :depth: 2

Summary & Scope
---------------

This document explains how HAProxy and Elastic Load Balancer can be used in
Amazon Web Services to provide performant and secure termination of traffic
to an API service. The goal is to provide the following features:

- **DDoS Protection**: we use HAProxy to mitigate low to medium DDoS attacks, with
  sane limits and custom blacklist.

- **Application firewall**:  we perform a first level of filtering in HAProxy, that
  protects NodeJS against all sorts of attack, known and to come. This will be done
  by inserting a set of regexes in HAProxy ACLs, that get updated when the
  application routes are updated. Note that managing these ACLs will not impact
  uptime, or require redeployment.

- **SSL/TLS**: ELBs support the PROXY protocol, and so does HAProxy, which allows us
  to proxy the tcp connection to HAProxy. It gives us better TLS, backed by
  OpenSSL, at the cost of managing the TLS keys on the HAProxy instances.

- **Logging**: ELBs have limited support for logging. HAProxy, however, has excellent
  logging for TCP, SSL and HTTPS. We leverage the flexibility of HAProxy's logging
  to improve our DDoS detection capabilities. We also want to uniquely identify
  requests in HAProxy and NodeJS, and correlate events, using a `unique-id`.

Architecture
------------

Below is our target setup:

.. image:: haproxy-aws-arch-diagram.png
   :alt: architecture diagram

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
    POLICY_TYPE  ProxyProtocolPolicyType    Policy that controls whether to include the
                                            IP address and port of the originating request
                                            for TCP messages. This policy operates on
                                            TCP/SSL listeners only

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

.. code::

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

.. code::

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

.. code::

	log-format [%pid]\ [%Ts.%ms]\ %ac/%fc/%bc/%bq/%sc/%sq/%rc\ %Tq/%Tw/%Tc/%Tr/%Tt\ %tsc\ %ci:%cp\ %fi:%fp\ %si:%sp\ %ft\ %sslc\ %sslv\ %{+Q}r\ %ST\ %b:%s\ "%CC"\ "%hr"\ "%CS"\ "%hs"\ req_size=%U\ resp_size=%B

The format above will generate:

.. code::

	Mar 14 17:14:51 localhost haproxy[14887]: [14887] [1394817291.250] 10/5/2/0/3/0/0 48/0/0/624/672 ---- 1.10.2.10:35701 10.151.122.228:443 127.0.0.1:8000 logger - - "GET /v1/ HTTP/1.0" 404 fxa-nodejs:nodejs1 "-" "{||ApacheBench/2.3|over-100-active-connections,over-100-connections-in-10-seconds,high-error-rate,high-request-rate,|47B4176E:8B75_0A977AE4:01BB_5323390B_31E0:3A27}" "-" "" ireq_size=592 resp_size=787

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
* `%CC`: captured request cookies
* `%hr`: captured request headers
* `%CS`: captured response cookies
* `%hs`: captured response headers
* `%U`: bytes read from the client (request size)
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

.. code::

	# Insert a unique request identifier is the headers of the request
	# passed to the backend
	unique-id-format %{+X}o\ %ci:%cp_%fi:%fp_%Ts_%rt:%pid
	unique-id-header X-Unique-ID

This will add an ID that is composed of hexadecimal variables, taken from the
client IP and port, frontend IP and port, timestamp, request counter and PID.
An example of generated ID is **485B7525:CB2F_0A977AE4:01BB_5319CB0C_000D:27C0**.

The Unique ID is added to the request headers passed to the backend in the
`X-Unique-ID` header. We will also capture it in the logs, as a request header.

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
log headers and cookies, the `capture` parameters must be set in the
frontend.

Here is how we can capture headers sent by the client in the HTTP request.

.. code::

	capture request header Referrer len 64
    capture request header Content-Length len 10
	capture request header User-Agent len 64

Cookies can be captures the same way:

.. code::

	capture cookie mycookie123=  len 32

HAProxy will also add custom headers to the request, before passing it to the
backend. However, added headers don't get logged, because the addition happens
after the capture operation. To fix this issue, we are going to create a new
frontend dedicated to logging.

Logging in a separate frontend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

During processing of the request, we added custom headers, and we want these
headers to appear in the logs. One solution is to route all the request to a
secondary frontend that only does logging, and blocking or forwarding.

Classic setup:

 ::

                    {logging}
     request        +--------------+       +---------------+
    +-------------->|frontend      |+----->|backend        |      +---------+
                    |   fxa-https  |       |    fxa-nodejs |+---->|         |
                    +--------------+       +---------------+      | NodeJS  |
                                                                  |         |
                                                                  +---------+

Setup with separate logging frontend:

 ::

                    {no logging}
     request        +--------------+       +---------------+
    +-------------->|frontend      |       |backend        |      +---------+
                    |   fxa-https  |       |    fxa-nodejs |+---->|         |
                    +--------------+       +---------------+      | NodeJS  |
                           +                     ^                |         |
                           |                     |                +---------+
                           |                     |
                    +------v-------+       +-----+--------+
                    |backend       |+----->|frontend      |
                    |     logger   |       |   logger     |
                    +--------------+       +--------------+
                                             {logging}


At the end of the configuration of frontend `fxa-https`, instead of sending
requests to backend `fxa-nodejs`, we send them to backend `logger`.

.. code::

	frontend fxa-https
		...
		# Don't log here, log into logger frontend
		no log
		default_backend logger

Then we declare a backend and a frontend for `logger`:

.. code::

	backend logger
		server localhost localhost:55555 send-proxy

	# frontend use to log acl activity
	frontend logger
		bind localhost:55555 accept-proxy

		...

		capture request header Referrer len 64
		capture request header Content-Length len 10
		capture request header User-Agent len 64
		capture request header X-Haproxy-ACL len 256
		capture request header X-Unique-ID len 64

		# if previous ACL didn't pass and aren't whitelisted
		acl whitelisted req.fhdr(X-Haproxy-ACL) -m beg whitelisted,
		acl fail-validation req.fhdr(X-Haproxy-ACL) -m found
		block if !whitelisted fail-validation

		default_backend fxa-nodejs

Note the use of `send-proxy` and `accept-proxy` between the logger backend and
frontend, allowing to keep the information about the client IP.

**Isn't this slow and inefficient?**

Well, obviously, routing request through HAProxy twice isn't the most elegant
way of proxying. But in practice, this approach adds minimal overhead. Linux and
HAProxy support TCP splicing, which provides zero-copy transfer of data between
TCP sockets. When HAProxy forward the request to the logger socket, there is, in
fact, no transfer of data at the kernel level. Benchmark it, it's fast!

Rate limiting & DDoS protection
-------------------------------

One of the particularity of operating an infrastructure in AWS, is that control
over the network is very limited. Techniques such as BGP blackholing are not
available. And visibility over the layer 3 (IP) and 4 (TCP) is reduced. Building
protection against DDoS means that we need to block traffic further down the
stack, which consumes more resources. This is the main motivation for using ELBs
in TCP mode with the PROXY protocol: it gives HAProxy low-level access to the
TCP connection, and visibility of the client IP before parsing HTTP headers
(like you would traditionally do with X-Forwarded-For).

ELBs have limited resources, but simplify the management of public IPs in AWS.
By offloading the SSL & HTTP processing to HAProxy, we reduce the pressure on
ELB, while conserving the ability to manage the public endpoints through it.

HAProxy maintains tons of detailed information on connections. One can use this
information to accept, block or route connections. In the following section, we
will discuss the use of ACLs and stick-tables to block clients that do not
respect sane limits.

Automated rate limiting
~~~~~~~~~~~~~~~~~~~~~~~

The configuration below enable counters to track connections in a table where
the key is the source IP of the client:

.. code::

	# Define a table that will store IPs associated with counters
	stick-table type ip size 500k expire 30s store conn_cur,conn_rate(10s),http_req_rate(10s),http_err_rate(10s)

	# Enable tracking of src IP in the stick-table
	tcp-request content track-sc0 src

Let's decompose this configuration. First, we define a `stick-table` that
stores IP addresses as keys. We define a maximum size for this table
of 500,000 IPs, and we tell HAProxy to expire the records after 30 seconds. If
the table gets filled, HAProxy will delete records following the LRU logic.

The `stick-table` will store a number of information associated with the IP
address:

- `conn_cur` is a counter of the concurrent connection count for this IP.

- `conn_rate(10s)` is a sliding window that counts new TCP connections over a 10
  seconds period

- `http_req_rate(10s)` is a sliding window that counts HTTP requests over a 10
  seconds period

- `http_err_rate(10s)` is a sliding window that counts HTTP errors triggered by
  requests from that IP over a 10 seconds period

By default, the stick table declaration doesn't do anything, we need to send
data to it. This is what the `tcp-request content track-sc0 src` parameter does.

Now that we have tracking in place, we can write ACLs that run tests against the
content of the table. The examples below evaluate several of these counters
against arbitary limits. Tune these to your needs.

.. code::

	# Reject the new connection if the client already has 100 opened
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]over-100-active-connections, if { src_conn_cur ge 100 }

	# Reject the new connection if the client has opened more than 100 connections in 10 seconds
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]over-100-connections-in-10-seconds, if { src_conn_rate ge 100 }

	# Reject the connection if the client has passed the HTTP error rate
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]high-error-rate, if { sc0_http_err_rate() gt 100 }

	# Reject the connection if the client has passed the HTTP request rate
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]high-request-rate, if { sc0_http_req_rate() gt 500 }

HAProxy provides a lot of flexibility on what can be tracked in a `stick-table`.
Take a look at section `7.3.2. Fetching samples at Layer 4` from the doc to get
a better idea.

Querying tables state in real time
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tables are named after the name of the frontend or backend they live in. Our
frontend called `fxa-https` will have a table called `fxa-https`, that can be
queried through the stat socket:

.. code::

	# echo "show table fxa-https" | socat unix:/var/lib/haproxy/stats -
	# table: fxa-https, type: ip, size:512000, used:1
	0x1aa3358: key=1.10.2.10 use=1 exp=29957 conn_rate(10000)=43 conn_cur=1 http_req_rate(10000)=42 http_err_rate(10000)=42

The line above shows a table entry for key `1.10.2.10`, which is a tracked IP
address. The other entries on the line show the status of various counters that
we defined in the configuration.

Blacklists & Whitelists
~~~~~~~~~~~~~~~~~~~~~~~

Blacklist and whitelists are simple lists of IP addresses that are checked by
HAProxy as early on as possible. Blacklist are checked at the beginning of the
TCP connection, which allows for early connection drops, and also means that
blacklisting an IP always takes precedence over any other rule, including the
whitelist.

Whitelists are checked at the HTTP level, and allow to bypass ACLs and rate
limiting.

.. code::

	# Blacklist: Deny access to some IPs before anything else is checked
	tcp-request content reject if { src -f /etc/haproxy/blacklist.lst }

	# Whitelist: Allow IPs to bypass the filters
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]whitelisted, if { src -f /etc/haproxy/whitelist.lst }
	http-request allow if { src -f /etc/haproxy/whitelist.lst }

List files can contain IP addresses or networks in CIDR format.

.. code::

	10.0.0.0/8
	172.16.0.0/12
	192.168.0.0/16
	8.8.8.8

List files are loaded into HAProxy at startup. If you add or remove IPs from a
list, make sure to perform a soft reload.

.. code:: bash

	haproxy -f /etc/haproxy/haproxy.cfg -c && sudo haproxy -f /etc/haproxy/haproxy.cfg -sf $(pidof haproxy)

Protect against slow clients (Slowloris attack)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Slowloris is an attack where a client very slowly sends requests to the server,
forcing it to allocate resources to that client that are only not used. This
attack is commonly used in DDoS, by clients that send their requests characters
by characters. HAProxy can block these clients, by allocating a maximum amount
of time a client can take to send a full request. This is done with the `timeout
http-request` parameter.

.. code::

    # disconnect slow handshake clients early, protect from
    # resources exhaustion attacks
    timeout http-request 5s

URL filtering with ACLs
-----------------------

HAProxy has the ability to inspect requests before passing them to the backend.
This is limited to query strings, and doesn't support inspecting the body of a
POST request. But we can already leverage this to filter out unwanted traffic.

The first thing we need, is a list of endpoints sorted by HTTP method. This can
be obtained from the web application directly. Note that some endpoints, such as
`__heartbeat__` should be limited to HAProxy, and thus blocked from clients.

For now, let's ignore GET URL parameters, and only build a list of request
paths, that we store in two files: one for GET requests, and one for POST
requests.

`get_endpoints.lst`

.. include :: get_endpoints.lst
   :code: bash

`post_endpoints.lst`

.. include :: post_endpoints.lst
   :code: bash

In the HAProxy configuration, we can build ACLs around these files. The `block`
method takes a condition, as described in the Haproxy documentation, section
`7.2. Using ACLs to form conditions`.

.. code::

	# Requests validation using ACLs ---
	acl valid-get path -f /etc/haproxy/get_endpoints.lst
	acl valid-post path -f /etc/haproxy/post_endpoints.lst

	# block requests that don't match the predefined endpoints
	block unless METH_GET valid-get or METH_POST valid-post

`block` does the job, and return a 403 to the client. But if you want more
visibility on ACL activity, you may want to use a custom header as describe
later in this section.

Filtering URL parameters on GET requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

While HAProxy supports regexes on URLs, writing regexes that can validate URL
parameters is a path that leads to frustration and insanity. A much simpler
approach consists of using the `url_param` ACL provided by HAProxy.

For example, take the NodeJS endpoint below:

.. code:: javascript

    {
      method: 'GET',
      path: '/verify_email',
      config: {
        validate: {
          query: {
            code: isA.string().max(32).regex(HEX_STRING).required(),
            uid: isA.string().max(32).regex(HEX_STRING).required(),
            service: isA.string().max(16).alphanum().optional(),
            redirectTo: isA.string()
              .max(512)
              .regex(validators.domainRegex(redirectDomain))
              .optional()
          }
        }
      },
      handler: function (request, reply) {
        return reply().redirect(config.contentServer.url + request.raw.req.url)
      }
    },

This endpoints receives requests on `/verify_email` with the parameters `code`,
a 32 character hexadecimal, `uid`, a 32 character hexadecimal, `service`, a 16
character string, and `redirectTo`, a FQDN. However, only `code` and `uid` are
required.

In the previous section, we validated that requests on `/verify_email` must use
the method GET. Now we are taking the validation one step further, and blocking
requests on this endpoint that do not match our prerequisite.

.. code::

	acl endpoint-verify_email path /verify_email
	acl param-code urlp_reg(code) [0-9a-fA-F]{1,32}
	acl param-uid urlp_reg(uid) [0-9a-fA-F]{1,32}
	block if endpoint-verify_email !param-code or endpoint-verify_email !param-uid

The follow request will be accepted, everything else will be rejected with a
HTTP error 403.

.. code::

	https://haproxy_server/verify_email?code=d64f53326cec3a1af60166a929ca52bd&uid=d64f53326cec3a1af60166a929c3d7b2131561792b4837377ed2e0cde3295df2

Using regexes to validate URL parameters is a powerful feature. Below is another
example that matches an email addresses using case-insensitive regex:

.. code::

	acl endpoint-complete_reset_password path /complete_reset_password
	acl param-email urlp_reg(email) -i ^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$
	acl param-token urlp_reg(token) [0-9a-fA-F]{1,64}
	block if endpoint-complete_reset_password !param-email or endpoint-complete_reset_password !param-token or endpoint-complete_reset_password !param-code

Note that we didn't redefine `param-code` when we reused it in the `block`
command. This is because ACL are defined globally for a frontend, and can
be reused multiple times.

Filtering payloads on POST requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

POST requests are harder to validate, because they do not follow a predefined
format, but also because the client could be sending the body over a long period
of time, split over dozens of packets.

However, in the case of an API that only handles small POST payloads, we can at
least verify the size of the payload sent by the client, and make sure that
clients do not overload the backend with random data. This can be done using an
ACL on the content-length header of the request. The ACL below discard requests
that have a content-length larger than 5 kilo-bytes (which is already a lot of
text).

.. code::

	# match content-length larger than 5kB
	acl request-too-big hdr_val(content-length) gt 5000
	block if METH_POST request-too-big

Marking instead of blocking
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Blocking requests may be the preferred behavior in production, but only after a
grace period that allows you to build a traffic profile, and fine tune your
configuration. Instead of using `block` statements in the ACLs, we can insert a
header with a description of the blocking decision. This header will be logged,
and can be analyzed to verify that no legitimate traffic would be blocked.

As discussed in `Logging in a separate frontend`, HAProxy is unable to log
request header that it has set itself. So make sure to log in a separate
frontend if you use this technique.

The configuration below uses a custom header `X-Haproxy-ACL`. If an ACL matches,
the header is set to the name of the ACL that matched. If several ACLs match,
each ACL name is appended to the header, and separated by a comma.

At the end of the ACL evaluation, if this header is present in the request, we
know that the request should be blocked.

In the `fxa-https` frontend, we replace the `block` paramameters with the
following logic:

.. code::

	# ~~~ Requests validation using ACLs ~~~
	# block requests that don't match the predefined endpoints
	acl valid-get path -f /etc/haproxy/get_endpoints.lst
	acl valid-post path -f /etc/haproxy/post_endpoints.lst
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]invalid-endpoint, unless METH_GET valid-get or METH_POST valid-post

	# block requests on verify_email that do not have the correct params
	acl endpoint-verify_email path /v1/verify_email
	acl param-code urlp_reg(code) [0-9a-fA-F]{1,32}
	acl param-uid urlp_reg(uid) [0-9a-fA-F]{1,32}
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]invalid-parameters, if endpoint-verify_email !param-code or endpoint-verify_email !param-uid

	# block requests on complete_reset_password that do not have the correct params
	acl endpoint-complete_reset_password path /v1/complete_reset_password
	acl param-email urlp_reg(email) -i ^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$
	acl param-token urlp_reg(token) [0-9a-fA-F]{1,64}
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]invalid-parameters, if endpoint-complete_reset_password !param-email or endpoint-complete_reset_password !param-token or endpoint-complete_reset_password !param-code

	# block content-length larger than 500kB
	acl request-too-big hdr_val(content-length) gt 5000
	http-request add-header X-Haproxy-ACL %[req.fhdr(X-Haproxy-ACL,-1)]request-too-big, if METH_POST request-too-big

Note the `%[req.fhdr(X-Haproxy-ACL,-1)]` parameter, that retrieves the value of
the latest occurence of the `X-Haproxy-ACL` header, so we can append to it and
store it again. However, this will create multiple headers if more than one ACL
is matched, but that's OK because:
- we can delete them before sending the request to the backend, using `reqdel`
- the logging directive `capture request header` will only log the last occurence

.. code::

	X-Haproxy-ACL: over-100-active-connections,
	X-Haproxy-ACL: over-100-active-connections,over-100-connections-in-10-seconds,
	X-Haproxy-ACL: over-100-active-connections,over-100-connections-in-10-seconds,high-error-rate,
	X-Haproxy-ACL: over-100-active-connections,over-100-connections-in-10-seconds,high-error-rate,high-request-rate,

Then, in the logger frontend, we check the value of the header, and block if
needed.

.. code::

	# frontend use to log acl activity
	frontend logger
		...
		# if previous ACL didn't pass, and IP isn't whitelisted, block the request
		acl whitelisted req.fhdr(X-Haproxy-ACL) -m beg whitelisted,
		acl fail-validation req.fhdr(X-Haproxy-ACL) -m found
		block if !whitelisted fail-validation

HAProxy management
------------------

Enabling the stat socket
~~~~~~~~~~~~~~~~~~~~~~~~

Collecting statistics
~~~~~~~~~~~~~~~~~~~~~

Analyzing errors
~~~~~~~~~~~~~~~~

Parsing performance metrics from the logs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

.. include:: haproxy.cfg
   :code: bash

Building process
----------------

Static build
~~~~~~~~~~~~
The following script builds haproxy with statically linked OpenSSL and PCRE
support.

.. include:: build_static_haproxy.sh
	:code: bash

Dynamic build
~~~~~~~~~~~~~
Same as above, but links to PCRE and OpenSSL dynamically.

.. include:: build_dynamic_haproxy.sh
   :code: bash

RPM build
~~~~~~~~~
Using the spec file and bash scripts below, we can build a RPM package using
for the latest development version of HAProxy.

`build_rpm.sh`

.. include:: build_rpm.sh
   :code: bash

`haproxy.spec`

.. include:: haproxy.spec
   :code: bash
