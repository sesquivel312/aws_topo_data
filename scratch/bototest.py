#!/usr/bin/env python
import sys
import getpass
import os
import platform
import pprint as pp

FLAG_URL_ENCODE_USER_INFO = False # url encode the username and password?
FLAG_PROMPT_FOR_PROXY = False  # set True to prompt user for proxy user and pwd

PROXY_HOST = 'ats01'
PROXY_PORT = '8080'

if platform.system() == 'Windows':
    BOTO_CORE = 'C:\\Users\\steve\\Anaconda2\\envs\\aws\\Lib\\site-packages\\botocore'
    BOTO_BOTO3 = 'C:\\Users\\steve\\Anaconda2\\envs\\aws\\Lib\\site-packages\\boto3'
    CA_BUNDLE = 'C:\\Users\\steve\\dev\\certs\\ec2us-west-2amazonawscom.crt'
else:
    BOTO_CORE = '/home/steve/dev/botocore'
    BOTO_BOTO3 = '/home/steve/dev/boto3'
    CA_BUNDLE = '/home/steve/certs/ec2us-west-2amazonawscom.crt'

sys.path.insert(0, BOTO_CORE)
sys.path.insert(0, BOTO_BOTO3)


import boto3

os.environ['REQUESTS_CA_BUNDLE'] = CA_BUNDLE

kid = getpass.getpass('AWS KID: ')
sk = getpass.getpass('AWS Secret Key: ')

if FLAG_PROMPT_FOR_PROXY:
    proxy_host = getpass.getpass('Enter proxy host name: ')
    proxy_port = getpass.getpass('Enter proxy port number: ')
else:
    proxy_host = PROXY_HOST
    proxy_port = PROXY_PORT

proxy_user = getpass.getpass('Enter proxy user ID: ')
proxy_pwd = getpass.getpass('Enter proxy pwd: ')

if proxy_user and proxy_port:  # deal with proxy auth user info
    if FLAG_URL_ENCODE_USER_INFO:
        user_info = urllib.quote('{}:{}'.format(proxy_user, proxy_pwd))
    else:
        user_info = '{}:{}'.format(proxy_user, proxy_pwd)
    proxy_url = 'https://{}@{}:{}'.format(user_info, proxy_host, proxy_port)
else:  # no proxy auth info
    proxy_url = 'https://{}:{}'.format(proxy_host, proxy_port)

os.environ['https_proxy'] = proxy_url

s = boto3.session.Session(aws_access_key_id=kid, aws_secret_access_key=sk, region_name='us-west-2')
ec2 = s.resource('ec2')

for vpc in ec2.vpcs.all():
    print vpc
