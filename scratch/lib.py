import hashlib
import datetime
import hmac
import argparse
import getpass
import requests
import urllib


PROXY = {'https': 'https://{}corpw_proxy.ews.int:8080'}

def get_cli_args():
    p = argparse.ArgumentParser()
    p.add_argument('-r', help='aws REGION against which this request will be made, '
                              'default: us-west-2', default='us-west-2')
    p.add_argument('-s', help='aws SERVICE against which this request will be made, '
                              'default: ec2', default='ec2')

    args = p.parse_args()
    region = args.r
    service = args.s

    return region, service


def get_ask_keys():
    """
    collects key ID and secret key from CLI

    :return: tuple (key_id, secret_key)
    """

    key_id = raw_input('Enter key ID: ')
    key = getpass.getpass('Enter secret key: ')

    return key_id, key


def get_proxy_creds():
    uid = raw_input('Enter Proxy UID: ')
    pwd = getpass.getpass()

    return uid, pwd


def get_aws_date_time():
    aws_datetime = datetime.datetime.today().isoformat().replace('-', '').replace(':', '').split('.')[0] + 'Z'
    aws_date = aws_datetime.split('T')[0]

    return aws_datetime, aws_date


def generate_canonical_request(canonical_request_prefix, body_string, aws_algo='AWS4-HMAC-SHA256'):

    if aws_algo.endswith('SHA256'):  # currently only supports sha256
        mode = getattr(hashlib, 'sha256')

    body_hash = mode(body_string).hexdigest()

    canonical_request = canonical_request_prefix + '\n' + body_hash  # no new-line at end

    return canonical_request


def generate_string_to_sign(region, service, date_time_tuple, canonical_request, aws_algo='AWS4-HMAC-SHA256'):
    """
    generate the string that is signed, that will ultimately be attached to the api request

    as a side effect the credential scope is created, which is itself needed when sending the final requeset, so that
    is returned along with the string-to-sign

    :param region: string - aws region targeted for request, e.g. 'us-west-2'
    :param service: string - aws service queried, e.g. 'ec2'
    :param date_time_tuple: tuple of date-time & date only,
    :param canonical_request: this is an HTTP request in the required AWS "canonical" form
    :param aws_algo: algorithm used for hash and mac, in AWS "syntax"
    :return: tuple: scope_string, string_to_sign
    """

    if aws_algo.endswith('SHA256'):
        mode = getattr(hashlib, 'sha256')

    string_to_sign = aws_algo + '\n'

    string_to_sign += date_time_tuple[0] + '\n'  # first member of tuple is a datetime string

    # 2nd member of the tuple is a date string only (no time part)
    scope_string = '{}/{}/{}/{}'.format(date_time_tuple[1], region, service, 'aws4_request')
    string_to_sign += scope_string + '\n'

    string_to_sign += mode(canonical_request).hexdigest()

    return scope_string, string_to_sign


def generate_signing_key(aws_secret, date_time_tuple, region, service, mode):

    kdate = hmac.new('AWS4' + aws_secret, date_time_tuple[1], mode)  # 2nd val of tuple is a date only

    kregion = hmac.new(kdate.digest(), region, mode)

    kservice = hmac.new(kregion.digest(), service, mode)

    sig = hmac.new(kservice.digest(), 'aws4_request', mode)

    return sig.digest()


def generate_signature(aws_secret, string_to_sign, date_time_tuple, region, service, aws_algo='AWS4-HMAC-SHA256'):

    if aws_algo.endswith('SHA256'):
        mode = getattr(hashlib, 'sha256')

    signing_key = generate_signing_key(aws_secret, date_time_tuple, region, service, mode)

    return hmac.new(signing_key, string_to_sign, mode).hexdigest()


def generate_authorization_string(key_id, scope, signed_headers_string, signature_string, aws_algo='AWS4-HMAC-SHA256'):

    auth_string = 'Authorization: {} Credential: {}/{}, SignedHeaders={}, Signature={}'.format(
        aws_algo, key_id, scope, signed_headers_string, signature_string
    )

    return auth_string


def send_request(request_data):

    proxy_user = request_data['auth'][0]
    proxy_pwd = request_data['auth'][1]
    proxy_auth_text = '{}:{}'.format(proxy_user, proxy_pwd)
    proxy_auth_text = urllib.quote(proxy_auth_text) + '@'

    PROXY['https'] = PROXY['https'].format(proxy_auth_text)

    # verify certs when c_rehash script is fixed
    return requests.get(request_data['url'], proxies=PROXY,
                        headers=request_data['headers'], verify=False)
