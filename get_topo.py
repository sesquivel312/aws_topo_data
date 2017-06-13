#!/usr/bin/env python
# todo P1 identify subnets that assign public IP's in renderings
# todo P2 edges from nat gateways to their subnet (necessary to see how they lead out of the VPC)
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
import datetime as dt

import pdb
import pprint as pp
import networkx as nx

import boto3

import lib

# globals
# todo P2 move the log setup to a function in lib.py if possible
# todo P3 adjust log configuration to include the time at execution
# todo P3 check for IPV6 addresss availability @ VPC level

TZ_DATA = lib.get_tz_data()
APP_NAME = os.path.split(__file__)[1]
LOG_MSG_FORMAT_STRING = '%(asctime)s {tzdata} {app_name} %(message)s'.format(tzdata=TZ_DATA, app_name=APP_NAME)
LOG_TIMESTAMP_FORMAT_STRING = '%Y-%m-%d %H:%M:%S'

#get run-time
run_time = dt.datetime.now()
run_time_string = dt.date.strftime(run_time, '%Y%m%d%H%M')

# create loggers
log_general = logging.getLogger('aws_topo')  # root/general logger
log_rule_check_report = logging.getLogger('aws_topo.check_report')  # rule check report log
log_rule_check_report.propagate = False  # don't duplicate messages in parent loggers


args = lib.get_args()

# setup config/handling for root logger
try:
    if args.output_dir:
        os.makedirs(args.output_dir)  # use makedirs in case user specified a path rather than simply a directory name
    else:
        args.output_dir = os.getcwd()  # use current directory
except OSError:
    pass  # assume exception means directory exists, if there are other reasons for the exception then fix this

if args.run_name: # file name "tag" specified
    args.log_file = os.path.join(args.output_dir, 'general-' + args.run_name + '-' + args.region + '-' + run_time_string + '.log')
    rule_check_rpt_fname = os.path.join(args.output_dir, 'rulechk-' + args.run_name + '-' + args.region + '-' +
                                        run_time_string + '.log')
    net_dump_fname = os.path.join(args.output_dir, 'net_dump-' + args.run_name + '-' + args.region + '-' +
                                  run_time_string + '.log')
    if args.export_rules:
        rule_export_fname = os.path.join(args.output_dir, 'rules-' + args.run_name + '-' + args.region + '-' +
                                         run_time_string + '.csv')
    else:
        rule_export_fname = None

    if args.instance_inventory_only:
        inventory_fname = os.path.join(args.output_dir, 'instances-' + args.run_name + '-' + args.region + '-' +
                                       run_time_string + '.csv')

else:
    args.log_file = os.path.join(args.output_dir, 'general-' + args.region + '-' + run_time_string + '.log')
    rule_check_rpt_fname = os.path.join(args.output_dir, 'rulechk-' + args.region + '-' + run_time_string + '.log')
    net_dump_fname = os.path.join(args.output_dir, 'net_dump-' + args.region + '-' + run_time_string + '.log')
    if args.export_rules:
        rule_export_fname = os.path.join(args.output_dir, 'rules-' + args.region + '-' + run_time_string + '.csv')
    else:
        rule_export_fname = None

    if args.instance_inventory_only:
        inventory_fname = os.path.join(args.output_dir, 'instances-' + args.region + '-' + run_time_string + '.csv')

logging.basicConfig(format=LOG_MSG_FORMAT_STRING, datefmt=LOG_TIMESTAMP_FORMAT_STRING,
                    filename=args.log_file, filemode='w', level=logging.INFO)  # filename=general_log_file, filemode='w'

# It appears that disabling propagation also stops logging from using previous format info as well, so create it
rule_check_log_fmt = logging.Formatter(fmt=LOG_MSG_FORMAT_STRING, datefmt=LOG_TIMESTAMP_FORMAT_STRING)

# now have all the info we need to crate, configure and apply the logging handler
rule_check_log_handler = logging.FileHandler(rule_check_rpt_fname, mode='w')
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

# get boto3 collections of vpcs and security-groups, which are iterable
vpcs, sec_groups = lib.get_vpcs_and_secgroups(session=aws_session)

log_general.info('Successfully gathered VPCs and security-groups')

if args.instance_inventory_only:
    lib.get_instance_inventory(vpcs, inventory_fname, aws_session)
    sys.exit()

networks = {}

# collect all the topo and related meta data
lib.build_nets(networks, vpcs, aws_session, args.keep_instance_inventory)

lib.get_sec_group_rules_by_subnet(networks, sec_groups)

lib.get_nacls(networks, vpcs)

lib.execute_rule_checks(networks)

# dump network data to file
with open(net_dump_fname, 'w') as f:
    lib.dump_network_data(networks, f)

if args.graph_format:
    lib.render_nets(networks, args.graph_format, run_time_string, args.region,
                    output_dir=args.output_dir, run_name=args.run_name)

if args.export_rules:
    lib.export_access_control_rules(networks, rule_export_fname)

