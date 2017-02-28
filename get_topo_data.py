#!/usr/bin/env python
# todo: verify refactor of the subnet data gathering is working correctly - in particular the security group list bits
# todo in graphs make size of subnets (circle?) reflect # of hosts (or maybe some other metric)
# todo refactor node data so it's grouped by type - e.g. data = {'route_tables': {<datahere>}, 'inet_gws': {<datahere>}, ...} << this will allow me to access just those types of nodes, rather than having ot constantly iterate over all of them and check each one's type
# todo start looking for "connections" to other accounts - could be other EW accounts but to non-ew accounts would be more interesting
import sys

import boto3

import support as ewaws

# filling this dict is what this script is all about
# dict(vpc-id: nx.Graph), one per vpc
networks = {}

args = ewaws.get_args()
key_id, key = ewaws.get_aws_api_credentials()

if key_id == None or key == None:
    sys.exit('Invalid Credentials')

# create sessions & client for later use
#  using session b/c  enables selection of aws profile
aws_session = boto3.session.Session(aws_access_key_id=key_id, aws_secret_access_key=key, region_name=args.region)

# get top level aws objects; they are iterables
vpcs, sec_groups = ewaws.get_vpcs_and_secgroups(aws_session=aws_session)

ewaws.build_nets(networks, vpcs, aws_session)  # this does most of the work

ewaws.collect_subnet_rules(networks, sec_groups)

ewaws.render_nets(networks, args.graph_format, output_dir=args.output_dir, yaml_export=args.export_network_to_yaml,
                  csv_file=args.csv_file)

# need to finish this function up before I use it :)
ewaws.execute_rule_checks(networks)
