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
#
#  Then you would edit this script as follows
#
#       <acctpfx1> = prod
#       <acctpfx2> = dev
#
# Notes:
#
#   - Of course you can add as many accounts as you like, you may want to add some hierarchy to the
#     the prefixes - if you have personal and work accounts you want to act on simultaneously.  For example, if
#     you have work dev and personal dev, maybe you use the prefixes wkdev and mydev, respectively
#
#   - Actual account prefixes aren't used here in order to prevent putting any "personally identifiable information"
#     into GitHub
#
#   - This script is most useful if your accounts don't change much (since you have to keep ending it in if they do)

# todo P1 read the account prefixes from a file?

case "$1" in
    <acctprx1>)
        export AWS_ACCESS_KEY_ID=$<acctpfx1>_id
        export AWS_SECRET_ACCESS_KEY=$<acctpfx1>_key
        ;;

    <acctprx2>)
        export AWS_ACCESS_KEY_ID=$<acctpfx2>_id
        export AWS_SECRET_ACCESS_KEY=$<acctpfx2>_key
        ;;

esac