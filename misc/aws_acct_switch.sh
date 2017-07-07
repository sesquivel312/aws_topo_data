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
#   - If the user enters the token code right before it expires it's possible they'll need to run again as
#     the code could expire between time code is collected and the aws CLI command is run
#
#   - Of course you can add as many accounts as you like, you may want to add some hierarchy to the
#     the prefixes - if you have personal and work accounts you want to act on simultaneously.  For example, if
#     you have work dev and personal dev, maybe you use the prefixes wkdev and mydev, respectively
#
#   - Setups up per-account variables AND per-account session variables; the latter hold the temp creds; the
#     session versions are prefixed like so: <acctpfx>_s_{id,key,token}
#
#   - This script is most useful if your accounts don't change much (since you have to keep ending it in if they do)

# todo P2 parameterize this so code isn't repeated - possibly read prefixes from file

case "$1" in
    <acctpfx1>)  # full(er) account name

        #export the permanent keys
        export AWS_ACCESS_KEY_ID=${<acctpfx1>_id}
        export AWS_SECRET_ACCESS_KEY=${<acctpfx1>_key}
    
        # if don't already have session vars, create them
        if [[ -z ${<acctpfx1>_s_token} ]]  # check no session token yet
            then
                read -p "Enter MFA Code: " TCODE  # prompt for and store MFA token code
                read <acctpfx1>_s_{id,key,token} <<< \  # read the session id, key and token values into variables
                    $(aws sts get-session-token --serial-number ${<acctpfx1>_mfa} \  # using AWS CLI & expanding vars
                    --token-code ${TCODE} | ~/dev/aws_topo_data/misc/parse_aws_tmp_creds.py)
                export <acctpfx1>_s_{id,key,token}  # make environment vars so available in child shells
        fi
    
        # we have session variables, set the AWS variables to those values
        export AWS_ACCESS_KEY_ID=${<acctpfx1>_s_id}
        export AWS_SECRET_ACCESS_KEY=${<acctpfx1>_s_key}
        export AWS_SESSION_TOKEN=${<acctpfx1>_s_token}

        ;;

    <acctpfx2>)  # full(er) account name

        #export the permanent keys
        export AWS_ACCESS_KEY_ID=${<acctpfx2>_id}
        export AWS_SECRET_ACCESS_KEY=${<acctpfx2>_key}

        # if don't already have session vars, create them
        if [[ -z ${<acctpfx2>_s_token} ]]
            then
                read -p "Enter MFA Code: " TCODE
                read <acctpfx2>_s_{id,key,token} <<< \
                    $(aws sts get-session-token --serial-number ${<acctpfx2>_mfa} \
                    --token-code ${TCODE} | ~/dev/aws_topo_data/misc/parse_aws_tmp_creds.py)
                export <acctpfx2>_s_{id,key,token}
        fi

        # we have session variables, set the AWS variables to those values
        export AWS_ACCESS_KEY_ID=${<acctpfx2>_s_id}
        export AWS_SECRET_ACCESS_KEY=${<acctpfx2>_s_key}
        export AWS_SESSION_TOKEN=${<acctpfx2>_s_token}

        ;;

esac