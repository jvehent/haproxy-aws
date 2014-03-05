==============================================
HAProxy termination in AWS: technical overview
==============================================

Building process
----------------
The following script builds haproxy with statically linked OpenSSL and PCRE
support.

.. include:: build_static_haproxy.sh
	:code: bash

Configuration sample
--------------------

.. include:: haproxy.cfg
   :code: bash
