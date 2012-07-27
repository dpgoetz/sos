Swift Origin Server
===================

    Copyright (c) 2012 OpenStack, LLC.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

.. toctree::
   :maxdepth: 2

   license

Overview
--------

A WSGI Middleware that provides access to customer containers in Swift for use
by a CDN service.  Uses Swift itself as its back-end store.

Getting Started
---------------

Copy the etc/sos.conf-sample to /etc/swift/sos.conf and make the changes to
your proxy.conf as shown in etc/proxy-server.conf-sample.

Reload your proxy-server
``swift-init proxy reload``

Prepare the environment:
``swift-origin-prep -K password``

You make requests to the cdn management interface by using the origin_db.com
hostname. To cdn-enable a container, do a container PUT just like you would in
swift except add the header 'Host: origin_db.com' to the request. When
you do a HEAD request you will see the cdn url returned as a header.

For example on a SAIO:
Get/set token:
``export AUTH_TOKEN=[AUTH_token]``
``export AUTH_USER=[AUTH_user]``

Put container in swift:
``curl -i -H "X-Auth-Token: $AUTH_TOKEN" http://127.0.0.1:8080/v1/$AUTH_USER/pub -XPUT``

Put object in container:
``curl -i -H "X-Auth-Token: $AUTH_TOKEN" http://127.0.0.1:8080/v1/$AUTH_USER/pub/file.html -XPUT -d '<html><b>It Works!!</b></html>'``

CDN enabled the container:
``curl -i -H "X-Auth-Token: $AUTH_TOKEN" http://127.0.0.1:8080/v1/$AUTH_USER/pub -XPUT -H 'Host: origin_db.com'``

Make origin request:
``curl http://127.0.0.1:8080/file.html -H 'Host: c0cd095b4ec76c09a6549995abb62558.r56.origin_cdn.com'``

Setting up Logging
------------------
If you want to add separate logging for SOS in a SAIO edit your rsyslog conf
to add a new section.

#. Edit /etc/rsyslog.d/10-swift.conf::

    local6.*;local6.!notice /var/log/swift/sos.log
    local6.notice           /var/log/swift/sos.error
    local6.*                ~

Building Packages
-----------------

1. Using python-stdeb: 
    To build packages ``sudo easy_install stdeb``

    cd into sos directory and run: ``python setup.py --command-packages=stdeb.command bdist_deb``

2. Using debuild: 
    First install ``apt-get install build-essential devscripts dh-make``

    Rename the sos directory to sos-VERSION  

    Create the original tarball: ``tar --exclude=debian -zcvf sos-VERSION.orig.tar.gz``

    Then cd into sos-VERSION directory and run ``debuild -us -uc``

    This will build the package without signing with your GPG key. 
    Keep in mind that it is a good idea to have your GPG key ready when building packages.
    It might complain that you don't have the necessary build dependencies, if so, install them.

    Ref: ``http://wiki.debian.org/IntroDebianPackaging``


Testing
-------

Unittests can be run from the sos directory with:
``./.unittests``


Functional tests can be run from the sos directory with:
``./.functests``

Functional tests use the same /etc/swift/func_test.conf as swift.  If
you are going to use sos with swift's staticweb middleware add the following
to the end of that file:

``sos_static_web = true``

Code-Generated Documentation
----------------------------

.. toctree::
    :maxdepth: 2

    sos
    sos_origin

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
