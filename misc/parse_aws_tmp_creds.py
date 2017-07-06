#!/usr/bin/env python
"""
when multi-factor auth applies to API access it is necessary to obtain a 
session-token, which replaces the normal API keys used to access the API for some time period
set by the IAM policy.  The API returns a JSON object, which this script parses and sends to standard out
as a single string, with spaces delimiting the necessary items (key id, key, session token)

Usage:

    parse_aws_tmp_creds
    

Example:
    
    <stuff> | parse_aws_creds.py
    
    <id_string> <key_string> <token_string>
    
    <stuff> is some command, e.g. aws cli command get-session-token, that will output a JSON object containing the 
    temp creds to STDOUT, which is parsed by this script
    


"""
import json
import sys

token_json = sys.stdin.readlines()  # get the temp creds from STDIN

token_dict = json.loads(token_json)
token_dict = token_dict['Credentials']  # just need the "guts"


sys.stdout.write(' '.join([token_dict['AccessKeyId'], token_dict['SecretAccessKey'], token_dict['SessionToken']]))