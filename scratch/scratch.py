import getpass
import urllib

import boto3

kid = getpass.getpass('Enter key ID: ')
skey = getpass.getpass('Enter sec. key: ')
uid = getpass.getpass('Enter proxy uid: ')
pwd = getpass.getpass('Enter proxy pwd: ')

userinfo = urllib.quote('{}:{}'.format(uid, pwd))

proxy_url = 'https://{}@localhost:8080'.format(userinfo)

proxies = {'https': proxy_url}

s = boto3.session.Session(aws_access_key_id=kid, aws_secret_access_key=skey, region_name='us-west-2')
ec2 = s.resource('ec2')

vpcs = ec2.vpcs.all()

for i in vpcs:
    print i.id
    break