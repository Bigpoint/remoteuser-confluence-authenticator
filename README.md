remoteuser-confluence-authenticator
===================================

Custom authenticator for confluence providing usage of remote_user variable. We use this as an easy way to utilize a reverse proxy for authentication.
We assume that we can read a remote_user header written by that reverse proxy in order to propagate the user name of the authenticated user.

Installation
============

1. Compile
2. Put the rsulting jar in your confluence/WEB-INF/lib folder
3. Edit seraph-config.xml in confluence/WEB-INF/classes to use this authenticator instead of the standard one: '<authenticator class="net.bigpoint.atlassian.confluence.RemoteUserAuthenticator"/>'

We use Apache as reverse proxy in this case. We ended up with the following vhost snippet:

    RewriteEngine On
    RewriteCond %{LA-U:REMOTE_USER} (.+)
    RewriteRule . - [E=RU:%1]
    RequestHeader set REMOTE_USER "%{RU}e" env=RU

It did not work in any way within our setup to use request.getRemoteUser(), so we decided to explicitly read the remote_user header.
There were some hints but everything we tried turned out to fail. So if you have a better idea, go ahead.

Kudos
=====

The unit tests of the confluence-siteminder-authenticator project by Matt Ryall were really helpful since I did not use Mockito so far but desperately needed mocking here.
Find that great project in Bitbucket: https://bitbucket.org/mryall/confluence-siteminder-authenticator

License and Author
==================

Author: Nils Hofmeister nhofmeister@bigpoint.net

Copyright 2013, Bigpoint GmbH

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

