#!/usr/bin/env bash

# set aws api credential environment variables to a specific account
#
# Usage:
#
#   aws_acct_switch <acctpfx>
#
# when testing scripts against the AWS API it's convenient to set environment variables that boto3 will use for
# authentication rather than manually entering API credentials for each run of a command or script.
#
# this script works by setting the necessary boto3/aws CLI environment variables to the values of other, existing
# environment variables that are named in a specific way
#
# Example:
#
#   Assume you have two accounts that you refer to as prod and dev (and you have keys API keys)
#
#   First, export environment variables for the key ID and secret keys using the format (don't end up w/keys in your
#   bash history):
#
#       <pfx>_<cred_type>
#
#       <pfx> is some prefix string that corresponds to the account name and
#       <cred_type> is: id | key
#
#   In this case you might export variables as follows:
#
#       export dev_id=<your dev account key ID here>
#       export dev_key=<your dev acct key here>
#       export dev_mfa=<your dev acct MFA device serial number>  // see below for why
#
#  Then you would edit this script as follows
#
#       <acctpfx1> = prod
#       <acctpfx2> = dev
#
# Notes:
#
#   - This script will likely be run once for each account before the per-account session-tokens exist
#     and again multiple times per account after per account session token variables are set/exported - b/c
#     the per account key-id and secret-key variables are necessary to run the aws commands to generate the
#     session tokens, once obtained they can be set, per account, and this script can be run again to change to that
#     account.  When this is done the key-id and secret-key values will change from the API keys to the STS issued
#     temporary credentials
#
#   - Of course you can add as many accounts as you like, you may want to add some hierarchy to the
#     the prefixes - if you have personal and work accounts you want to act on simultaneously.  For example, if
#     you have work dev and personal dev, maybe you use the prefixes wkdev and mydev, respectively
#
#   - Actual account prefixes aren't used here in order to prevent putting any "personally identifiable information"
#     into GitHub
#
#   - To set the session tokens per account use the following commands to setup the session token variables
#     for each account.
#
#               read <acctpfx>_{id,key,token} <<< $(aws sts get-session-token --serial-number ${<acctpfx>_mfa} \
#               --token-code <current_MFA_code> | <path>/<to>/parse_aws_tmp_creds.py); export <acctpfx>_{id,key,token}
#
#     This command line says:
#
#       - Get a session token from AWS CLI for the mfa device with serial-number $<acctpfx>_mfa
#       - Parse that output (it's JSON) using the .py script - which will return (via STDIN) 3 values
#         separated by spaces (or whatever $IFS is set to), those are the values of the AWS key-id, key, session token
#       - send the parsed result to "read" which will set the shell variables named <acctpfx>_(id,key,token) to
#         the parsed values - in order given
#       - then export the shell variables (i.e. make them environment variables) w/the same names
#
#   - Given all the above, the way you'd use this script is:
#
#       1 customize misc/aws_acct_switch.sh for your accounts - SAVE IT OUTSIDE GIT'S SCOPE
#       2 export the id, key and mfa-serial-number variables per account
#       3 use aws_acct_switch.sh to switch to some account using an acct prefix as the argument
#       4 run the command above, i.e. read ...
#       5 repeat 3-4 for each account
#       6 you can now use aws_acct_switch.sh to switch to any account and the temp credentials will be used
#
#   - This script is most useful if your accounts don't change much (since you have to keep ending it in if they do)

# todo P2 read the account prefixes from a file?
# todo P1 code (steps 1-6) - likely need to have separate per account cred and "temp cred" variables

case "$1" in
    <acctprx1>)
        export AWS_ACCESS_KEY_ID=$<acctpfx1>_id
        export AWS_SECRET_ACCESS_KEY=$<acctpfx1>_key
        export AWS_SESSION_TOKEN=$<acctpfx1>_token
        ;;

    <acctprx2>)
        export AWS_ACCESS_KEY_ID=$<acctpfx2>_id
        export AWS_SECRET_ACCESS_KEY=$<acctpfx2>_key
        export AWS_SESSION_TOKEN=$<acctpfx2>_token

        ;;

esac