#!/usr/bin/env python

import getpass
import urllib
import os

import requests

FLAG_TEST_REQUESTS = True  # change to false to test Boto's requests
FLAG_URL_ENCODE_USER_INFO = False # url encode the username and password?


REQUESTS_ENDPOINT = 'https://www.cisco.com'
PROXY_HOST = 'ats01'
PROXY_PORT = '8080'
CA_BUNDLE_PATH = '/home/steve/certs/ec2us-west-2amazonawscom.crt'

kid = getpass.getpass('Enter key ID: ')
sec_key = getpass.getpass('Enter sec. key: ')
uid = getpass.getpass('Enter proxy uid: ')
pwd = getpass.getpass('Enter proxy pwd: ')

if FLAG_URL_ENCODE_USER_INFO:
    user_info = urllib.quote('{}:{}'.format(uid, pwd))
else:
    user_info = '{}:{}'.format(uid, pwd)

proxy_url = 'https://{}@{}:{}'.format(user_info, PROXY_HOST, PROXY_PORT)

proxies = {'https': proxy_url}

os.environ['HTTPS_PROXY'] = proxy_url

if FLAG_TEST_REQUESTS:
    r = requests.get(REQUESTS_ENDPOINT, verify=CA_BUNDLE_PATH)
else:
    s = boto3.session.Session(aws_access_key_id=kid, aws_secret_access_key=skey, region_name='us-west-2')
    ec2 = s.resource('ec2', verify=CA_BUNDLE_PATH)

    vpcs = ec2.vpcs.all()

    for i in vpcs:
        print i.id