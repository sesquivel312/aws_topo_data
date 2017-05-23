#!/usr/bin/env python
# todo P1 identify subnets that assign public IP's in renderings
# todo P2 add different colors/icons to pyplot images based on type of node
# todo P2 colorize the edges based on destination, e.g. red for lines to IGW, VPN, etc.
# todo P3 in graphs make size of subnets (circle?) reflect # of hosts (or maybe some other metric)
# todo P3 refactor node data so it's grouped by type - e.g. data = {'route_tables': {<datahere>} ...
#   'inet_gws': {<datahere>}, ...} << this will allow me to access just those types of nodes, rather...
#   than having to iterate and check type
# todo P3 start looking for "connections" to other accounts - could be other EW accounts but to non-ew ...
#   accounts would be more interesting
# todo P3 handle isolated nodes differently in visualizations, e.g. move to bottom, different color...
#   at least add flag to indicate this

import os
import sys
import logging
import pdb

import boto3

import lib

# globals
# todo P2 move the log setup to a function in lib.py if possible
# todo P3 adjust log configuration to include the time at execution
TZ_DATA = lib.get_tz_data()
APP_NAME = os.path.split(__file__)[1]
LOG_MSG_FORMAT_STRING = '%(asctime)s {tzdata} {app_name} %(message)s'.format(tzdata=TZ_DATA, app_name=APP_NAME)
LOG_TIMESTAMP_FORMAT_STRING = '%Y-%m-%d %H:%M:%S'

# create loggers
log_general = logging.getLogger('aws_topo')  # root/general logger
log_rule_check_report = logging.getLogger('aws_topo.check_report')  # rule check report log

# filling this dict is what this script is all about
# dict(vpc-id: nx.Graph), one per vpc
args = lib.get_args()


# setup config/handling for general/root logger
if not args.output_dir:  # if output dir CLI option not supplied, use the current directory
    args.output_dir = os.getcwd()

if not args.log_file:  # if no logfile CLI option supplied, log to the default 'general.log' in the current dir
    args.log_file = os.path.join(args.output_dir, 'general.log')
else:
    args.log_file = os.path.join(args.output_dir, args.log_file)

logging.basicConfig(format=LOG_MSG_FORMAT_STRING, datefmt=LOG_TIMESTAMP_FORMAT_STRING,
                    filename=args.log_file, filemode='w', level=logging.INFO)  # filename=general_log_file, filemode='w'

if args.rule_check_report:  # --rule-check-report option specified on CLI
    log_rule_check_report.propagate = False  # don't duplicate messages in parent loggers
    args.rule_check_report = os.path.join(args.output_dir, args.rule_check_report)  # prepare var holding log path/file

    # It appears that disabling propagation also stops logging from logging for format info as well, so create that
    rule_check_log_fmt = logging.Formatter(fmt=LOG_MSG_FORMAT_STRING, datefmt=LOG_TIMESTAMP_FORMAT_STRING)

    # now have all the info we need to crate, configure and apply the handler
    rule_check_log_handler = logging.FileHandler(args.rule_check_report, mode='w')
    rule_check_log_handler.setFormatter(rule_check_log_fmt)
    rule_check_log_handler.setLevel(logging.INFO)
    log_rule_check_report.addHandler(rule_check_log_handler)

key_id, key = lib.get_aws_api_credentials()

if key_id == None or key == None:
    sys.exit('Invalid Credentials')

log_general.info('Sucessfully obtained API credentials')

# create sessions & client for later use
#  using session b/c  enables selection of aws profile
aws_session = boto3.session.Session(aws_access_key_id=key_id, aws_secret_access_key=key, region_name=args.region)

log_general.info('Successfully created AWS session')

# get top level aws objects; they are iterables
vpcs, sec_groups = lib.get_vpcs_and_secgroups(session=aws_session)

log_general.info('Successfully gathered VPCs and security-groups')

networks = {}

# collect all the topo and related meta data
lib.build_nets(networks, vpcs, aws_session)

lib.get_sec_group_rules_by_subnet(networks, sec_groups)

lib.get_nacls(networks, vpcs)

# dump network data to file
net_dump_file = os.path.join(args.output_dir, 'net-dump.out')
with open(net_dump_file, 'w') as f:
    lib.dump_network_data(networks, f)

lib.render_nets(networks, args.graph_format, output_dir=args.output_dir, yaml_export=args.export_network_to_yaml,
                csv_file=args.export_rules)

# need to finish this function up before I use it :)
lib.execute_rule_checks(networks)
