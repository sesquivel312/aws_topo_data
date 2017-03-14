import sys
import getpass
import os
import pprint as pp

mybotocore = '/home/steve/dev/botocore'
myboto3 = '/home/steve/dev/boto3'

def get_path_index(list):
    for i, v in enumerate(list):
        if v.startswith('/usr'):
            return i

i = get_path_index(sys.path)

sys.path.insert(i, mybotocore)
sys.path.insert(i, myboto3)
os.environ['REQUESTS_CA_BUNDLE'] = '/home/steve/certs/owasp_zap_root_ca.cer'
print 'ca bundle envar: ', os.environ['REQUESTS_CA_BUNDLE']

import boto3

print 'boto3 location: ', boto3.__file__

kid = getpass.getpass('AWS KID: ')
sk = getpass.getpass('AWS Secret Key: ')

s = boto3.session.Session(aws_access_key_id=kid, aws_secret_access_key=sk, region_name='us-west-2')
ec2 = s.resource('ec2')

for vpc in ec2.vpcs.all():
    print vpc
