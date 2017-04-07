#!/usr/bin/env python

# manually test accessing a url via a proxy that is enforcing kerberos authentication
# the environment is as follows:
#     Windows server 2016 as domain controller (and DNS server)
#         domain = windom.local << .local was a mistake and I know better :(
#         domain user created for testing
#     Windows 10 workstation (enterprise)
#         add to domain
#         add domain user created to power users group (just to avoid some pain on client, not really relevant for this test)
#         install python, virtualenv, virtualenvrapper-win (or similar), requsts, requests-kerberos, boto3
#         install other tools as needed (e.g. git, wireshark, etc.)
#         configure OS level proxy to point to barracuda (see below)
#     Barracuda Web Security Gateway (wsg)
#         Note: kept default proxy port of 3128
#         hostname = barracuda.windom.local
#         add A/PTR record to DNS on winserver for this box
#         conigure unauthenticated policy to block basically everything
#         cfg exception policy to permit access to pypi
#         cfg authed prolicy to permit everything
#         cfg kerberos authentiction
#             realm: windom.
#             KDC: <winserverhostname>.windom.local
#             User: <domain admin user>  << user is needed to add machine to the domain
#             Pwd: <domain admin user pwd>
#
# note, so far (4/6/2017) I couldn't get requests_kerberos to work, I suspect
# that is either b/c I'm still not using it correctly or b/c it doesn't handle the proxy
# at all - i.e. it tries to auth to the origin server, not the proxy, ** INVESTIGATE **
# 
# Instead I followed the example here: http://python-notes.curiousefficiency.org/en/latest/python_kerberos.html  
# i.e. handling the kerberos bits manually, resulting in the code below
#
# at a high level I think what's happening is this...
# 
# I'm authenticated to the domain already
# I have a TGT already
# I'm just getting a service ticket for the proxy service from the KDC/Domain Controller
# then passing that to the proxy via the http proxy-authorization header
#
# I figured out the proxy service name by looking at the DC using 
#
#     setspn -L barracuda
#
# -L means list all the SPNs (service principal names) for the account given (barracuda in this case)
# NB: that's a windows command
# I assume that's registered by the proxy when you join it to the domain
# the output was:
#
#      Registered ServicePrincipalNames for CN=barracuda,CN=Computers,DC=windom,DC=local:
#              HTTP/barracuda.windom.local
#              HTTP/barracuda
#              HOST/barracuda.windom.local
#              HOST/BARRACUDA
#
# note the difference in representation of the service name as compared to "winkerberos",
# which is effectively using the GSSAPI, i.e. 'HTTP@barracuda.windom.local'
# 
# some other info
# there are at least two kerberos python packages:
#
#     kerbers/pykerberos and winkerberos
#
# all of them allegedly use the pykerberos API
# the winkerbers package is obviously for windows and uses the windows SSPI, which is not
# 100% equivalent to GSSAPI, but it's apparently close ??
#
# the way the API works is, I think ,the same as defined by the GSSAPI RFC (google it)
# high level it's like this (all from client perspecdtive) ...
#
# call the "init" method to get "context data", which is opaque, but I think is the service ticket
# call the "client step", I"m not clear on what this is doing. bit I think we want
#   to check the return value here, to be sure we successeded (which this test script does)
#   of we succeed, then ...
# call "client response", which returns the auth data we need to send to the server in
#   the http headers (proxy-authorization in this case)
#
# why the multiple test urls?
# depaul redirected to HTTPS, I just didn't want to handle the redirect for this test
# requests errored out decoding the result from asu - need to look into that
# noaa seemed to work (I hopeed they weren't doing anything funky on their home page)
#

import winkerberos as krb
import requests
import sys

url_sec_depaul = 'http://www.depaul.edu'
url_asu = 'http://www.asu.edu'
url_noaa = 'http://www.noaa.gov'

_, ctx = krb.authGSSClientInit('HTTP@barracuda.windom.local')

rcode = krb.authGSSClientStep(ctx, '')

if not rcode:  # result code of 0 means success 
	client_data = krb.authGSSClientResponse(ctx)
else:
	sys.exit('Failed at first client step')

proxies = {'all': 'http://barracuda.windom.local:3128'}
headers = {'proxy-authorization': 'Negotiate ' + client_data}

r = requests.get(url_noaa, headers=headers, proxies=proxies)

print 'status: ', r.status_code
print 'rep hdr: ', r.headers
print 'body: ', r.text

