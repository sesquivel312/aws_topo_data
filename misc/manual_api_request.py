import hashlib
import datetime
import hmac


def get_canonical_request(canonical_request_prefix, body_string):
    body_hash = hashlib.sha256(body_string).hexdigest()

    canonical_request = canonical_request_prefix + '\n' + body_hash + '\n'

    return canonical_request


def get_string_to_sign(region, service, canonical_request):
    aws_datetime = datetime.datetime.today().isoformat().replace('-', '').replace(':', '').split('.')[0] + 'Z'
    aws_date = aws_datetime.split('T')[0]

    string_to_sign = 'AWS4-HMAC-SHA256\n'
    string_to_sign += aws_datetime + '\n'
    string_to_sign += '{}/{}/{}/{}\n'.format(aws_date, region, service, 'aws4_request')
    string_to_sign += hashlib.sha256(string_to_sign).hexdigest()

    return string_to_sign


def aws_sig_key(aws_secret, date, region, service):
    kdate = hmac.new('AWS4' + aws_secret, date, hashlib.sha256)
    kregion = hmac.new(kdate.digest(), region, hashlib.sha256)
    kservice = hmac.new(kregion.digest(), service, hashlib.sha256)
    sig = hmac.new(kservice.digest(), 'aws4_request', hashlib.sha256)

    return sig.digest()


def get_payload_hash(body_string):
    return hashlib.sha256(body_string).hexdigest()


def gen_canonical_request(request_string, hashed_body):
    return request_string + '\n' + get_payload_hash(http_body)


def gen_string_to_sign():
    pass

# step 1 canonical request
# prefix = method\n + uri\n + query\n + headers\n\n + signed_headers_list\n


canonical_request_prefix = '''GET
/
Action=DescribeVpcs
host:ec2.us-west-2.amazonaws.com

host'''

body_string = ''

canonical_request = get_canonical_request(canonical_request_prefix, body_string)

# step 2 string to sign
# algorithm\n + requestdate\n + cred_scope\n + canonical_request_hash

string_to_sign = get_string_to_sign('us-west-2', 'ec2', canonical_request)


# step 3 >> http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

# step 4
