from ignore import lib

# ~~~~~ Build AWS request ~~~~~
# step 1 canonical request
# prefix = method\n + uri\n + query\n + headers\n\n + signed_headers_list\n

AWS_SIG_ALGO = 'AWS4-HMAC-SHA256'
API_ACTION = 'DescribeVpcs'  # this is part of the request but needed
API_URL = 'https://ec2.us-west-2.amazonaws.com/?Action=DescribeVpcs'
# would be better to build the cananical request from the action, url, etc. << future improvement
CANONICAL_REQ_PFX = """GET
/
Action=DescribeVpcs
host:ec2.us-west-2.amazonaws.com

host;x-amz-date"""

SIGNED_HDRS_STR = 'host;x-amz-date'

BODY_STR = ''

region, service = lib.get_cli_args()

aws_key_id, aws_secret_key = lib.get_ask_keys()

date_time_tuple = lib.get_aws_date_time()

canonical_request = lib.generate_canonical_request(CANONICAL_REQ_PFX, BODY_STR)

# step 2 string to sign
# algorithm\n + requestdate\n + cred_scope\n + canonical_request_hash

scope_string, string_to_sign = lib.generate_string_to_sign(region, service, date_time_tuple, canonical_request)

# step 3 create the signature

signature = lib.generate_signature(aws_secret_key, string_to_sign, date_time_tuple, region, service)

# step 4 create sig string for use in either header or query string of request

authorization = lib.generate_authorization_string(aws_key_id, scope_string, SIGNED_HDRS_STR, signature)

# ~~~~~ Send request to AWS

# get proxy proxy_creds
proxy_creds = lib.get_proxy_creds()  # returns a tuple: uid, pwd

# send request to aws using EW corp proxy
request_data = {
    'url': API_URL,
    'headers': {'x-amz-date': date_time_tuple[0], 'authorization': authorization},
    'auth': proxy_creds
}

r = lib.send_request(request_data)

print 'status code: ', r.status_code
print 'response headers:'
print r.headers
print '\n\nresponse text:'
print r.text
print '\n\nrequest headers:'
print r.request.headers

# print response status code & text/content




