#!/usr/bin/env python
# todo: verify refactor of the subnet data gathering is working correctly - in particular the security group list bits
# todo in graphs make size of subnets (circle?) reflect # of hosts (or maybe some other metric)
# todo refactor node data so it's grouped by type - e.g. data = {'route_tables': {<datahere>}, 'inet_gws': {<datahere>}, ...} << this will allow me to access just those types of nodes, rather than having to iterate and check type
# todo start looking for "connections" to other accounts - could be other EW accounts but to non-ew accounts would be more interesting
# todo treat isolated nodes in graphical display, e.g. move to bottom, different color, at least add flag to indicate this
# todo add different colors/icons to pyplot images based on type of node
# todo colorize the edges based on destination, e.g. red for lines to IGW, VPN, etc.

import sys
import pprint as pp

import boto3

import lib

# filling this dict is what this script is all about
# dict(vpc-id: nx.Graph), one per vpc
networks = {}

args = lib.get_args()

key_id, key = lib.get_aws_api_credentials()

if key_id == None or key == None:
    sys.exit('Invalid Credentials')

# create sessions & client for later use
#  using session b/c  enables selection of aws profile
aws_session = boto3.session.Session(aws_access_key_id=key_id, aws_secret_access_key=key, region_name=args.region)

# get top level aws objects; they are iterables
vpcs, sec_groups = lib.get_vpcs_and_secgroups(session=aws_session)

lib.get_nacls(vpcs)

# collect all the topo and related meta data
lib.build_nets(networks, vpcs, aws_session)

with open('output/net-dump.out', 'w') as f:
    lib.dump_network_data(networks, f)

lib.collect_subnet_rules(networks, sec_groups)

lib.render_nets(networks, args.graph_format, output_dir=args.output_dir, yaml_export=args.export_network_to_yaml,
                csv_file=args.csv_file)

# need to finish this function up before I use it :)
lib.execute_rule_checks(networks)
