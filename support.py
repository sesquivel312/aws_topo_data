"""
functions for compiling data from aws

Data is stored as attributes of a networkx graph, one network per AWS VPC (virtual private container).  Each graph
has a few graph-level attributes, specifically:

    vpc: vpc_id, which is a string of the form "vpc-hhh...", where hhh are hex digits
    cidr: the ip block associated w/the VPC
    isdefault: a T/F flag indicating if this is the default VPC (check AWS docs for this?)
    state: check AWS docs for the meaning of this

Each node in a graph has an associated, possibly empty attribute dictionary.  The structure of the attribute dict
depends on the "type" node.  Here "type" refers to the AWS object type, e.g. subnet, routing table, etc.

The currently used node types are listed below.  These will show up as graph nodes.

    subnet-hhhhh  (subnet)
    rtb-hhhhh  (route table)
    vgw-hhhhh  (vpn gateway)
    igw-hhhhh  (internet gateway)
    pcx-hhhhh  (peer connection)

Below are the structures of the various types, i.e. the data held by each of the node types listed above.

VPN Gateway:
    rtb: no attributes (empty dict)
    igw: no attributes (empty dict)
    pcx: {id: <pcx_id>, accepter_vpc_id: <avid>, requester_vpc_id: <rvid>}
    vgw: {id: <vgwid>, state: <state>}
    subnet: { avail_zone: <az>, cidr: <cidr>, assign_publics: <TF?>, state: <state>, sec_groups: <set_of_sec_groups>,
              inacl: [ {sgid: <secgrpid>, source: [s1,...], proto: <proto>, ports: (<range_start>,<range_end>)}, ...],
              outacl: [ same structure as inacl ] }
"""

import argparse
import os.path
import yaml
import csv
import getpass
import sys
import pprint as pp

import networkx as nx
import matplotlib.pyplot as plot


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', help='AWS region to use, defaults to us-west-2', default='us-west-2')
    parser.add_argument('--graph-format', help='Graph output format; no graph output produced if not specified, options'
                                               'include:\nprint, gephi, pyplot\nprint prints out the network info to'
                                               'the terminal')
    parser.add_argument('--output-dir', help='Path output is written to, current dir if not specified')
    parser.add_argument('--export-network-to-yaml', help='flag indicating network data should be exported to a YAML '
                                                         'file in the directory indicated by --output-dir (or current '
                                                         'directory if not specified', action='store_true')
    parser.add_argument('--csv-file', help='Export rules to csv formatted file named by the value to this argument')

    return parser.parse_args()


def get_aws_api_credentials():
    key_id = getpass.getpass('Enter key ID: ')
    key = getpass.getpass('Enter key: ')

    return key_id, key


def get_current_us_regions(aws_session=None):
    """
    query aws for currently extant regions
    :param aws_session:
    :return:
    """

    ec2_client = aws_session.client('ec2')

    us_regions = []
    for region in ec2_client.describe_regions()['Regions']:
        name = region['RegionName']
        if name.startswith('us-'):
            us_regions.append(name)
    return us_regions


def get_vpcs_and_secgroups(aws_session=None, region_name='us-west-2'):
    """
    retrieve VPC's and Subnets from aws account

    account comes from profiles in boto3 config

    :param key_id: aws api key id
    :param key: aws api secret key
    :param region_name: aws region from which to pull data
    :return:
    """

    # todo check for vpcs with 0 instances and filter them

    if not aws_session:
        sys.exit('*** No valid EC2 session available, aborting...')

    ec2_resource = aws_session.resource('ec2')  # is region inherited

    vpcs = ec2_resource.vpcs.all()  # .all() returns an iterable of all VPC objects associated w/the aws VPC
    sec_groups = ec2_resource.security_groups.all()

    return vpcs, sec_groups


def get_node_type(node_name):
    """
    helper function returning the type of node based on the node name/id

    :param node_name: string - name/id of node
    :return: node_type: string = inet_gw | peer_conn | router | subnet | vpn_gw | nat_gw
    """

    prefix = node_name.split('-')[0]

    if prefix == 'subnet':
        return 'subnet'
    elif prefix == 'rtb':
        return 'router'
    elif prefix == 'pcx':
        return 'peer_con'
    elif prefix == 'igw':
        return 'inet_gw'
    elif prefix == 'vgw':
        return 'vpn_gw'
    elif prefix == 'nat':
        return 'nat_gw'
    else:
        return None


def create_gateway_name(route_dict):
    """
    construct a gateway "name" from a dict of route attributes

    AWS routes have a number of attributes associated w/them. For the moment I can't tell
    which are mutex w/which-others.  E.g. if there's a value in the vpc peer conn id field must
    the gw-id field be None.  Rather than try to figure that out I'll construct a name from the
    various attributes by contactenting the route-attribute values into a single string.  If
    things go well there will only ever be one string that makes up the resulting gateway-name.
    If they don't go well, then the name will be something strange like vpx-abc123:igw-def321.

    Currently skipping any ??? == 'local'

    :param route_dict: dictionary of route attributes (see func populate_router_data)
    :return: gw_name: string
    """

    # get the non None values from the route attribute dict, that matter in identifying the gw "name"
    name_components = [v for k, v in route_dict.iteritems() if k in
                       ['gw_id', 'inst_id', 'pcx_id', 'nat_gw', 'egress_gw'] and v]

    return ':'.join(name_components)


def get_subnet_data(networks, vpc):
    """
    enumerate subnets in a given VPC, subsequently extract security groups (per subnet) and install in a dict of
    networkx network objects

    :param networks: networkx network object
    :param vpc: boto3.vpc
    :return: n/a
    """

    for subnet in vpc.subnets.all():  # from boto3 vpc subnets collection

        subnet_attribs = {'avail_zone': subnet.availability_zone, 'cidr': subnet.cidr_block,
                          'assign_publics': subnet.map_public_ip_on_launch, 'state': subnet.state,
                          'assoc_route_table': None}  # assoc route table used to find subnets assoc w/'main' rtb

        networks[vpc.id].add_node(subnet.id, **subnet_attribs)

        sec_group_set = set([])  # set of all security groups in this subnet

        # populate networkx network object with security groups
        for instance in subnet.instances.all():  # instance is a aws instance
            # get the security groups for this subnet
            # from the instances in it
            for group in instance.security_groups:
                sec_group_set.add(group['GroupId'])

        networks[vpc.id].node[subnet.id]['sec_groups'] = sec_group_set


def get_vpngw_data(networks, vpc, aws_session):
    """
    add aws vpn gateways as nodes and add associated metadata to associated networkx object

    :param networks: dict; {'vpc-id': networkx.Graph()}
    :param vpc: boto3.ec2.vpc
    :param aws_session: boto3.session object; communicates with AWS
    :return:
    """
    # must use ec2.client in order to access vpn gateway info
    ec2_client = aws_session.client('ec2')
    for vpngw in ec2_client.describe_vpn_gateways(Filters=[{'Name': 'attachment.vpc-id',
                                                            'Values': [vpc.id]}])['VpnGateways']:
        # get vpn gw's attached to this VPC and add them as nodes
        # want the availability zone but it's not always available
        vpngw_attributes = {'id': vpngw['VpnGatewayId'], 'state': vpngw['State']}  # want avail zone, but not always
        #                                                                            returned
        networks[vpc.id].add_node(vpngw['VpnGatewayId'], **vpngw_attributes)


def get_nat_gateways(network_obj, vpc_id, aws_session):
    """
    add nat gateway nodes to network, along w/any pertinent meta data

    NB: using session b/c I can't find any reference to nat gateways in the ec2-resource docs

    :param network_obj: a networkx graph representing the network topo in a single VPC
    :param aws_session: a boto3 session object
    :return:
    """

    # create the client from session
    ec2_client = aws_session.client('ec2')

    # get natgw iterable for this vpc  (list of dicts
    natgw_dict = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id, ]}])
    natgw_list = natgw_dict['NatGateways']  # list of dicts containing attributes of a given nat gateway

    # loop over and add as nodes, collecting desired metadata
    for gateway in natgw_list:
        attributes = {'state': gateway['State']}
        network_obj.add_node(gateway['NatGatewayId'], **attributes)


def get_inetgw_data(networks, vpc):
    for gateway in vpc.internet_gateways.all():
        networks[vpc.id].add_node(gateway.id)


def get_peering_conn_data(network_object, vpc):  # get vpc peering connections
    # todo determine how to represent multiple VPC's and the nodes w/in it - topo per account vs per vpc?
    # todo P2 verify collecting both accepter and requester vpc-id's and not overwriting data (check netwokx doco)


    nodes = network_object.node

    # add "requested" pcx'es
    for peer in vpc.requested_vpc_peering_connections.all():
        if peer.id not in nodes:  # if the pcx ID is not a key in the nodes dict, i.e. doesn't yet exist, add it
            requester_info = peer.requester_vpc_info  # reduce the # of dict sub-references typed by hand
            requester_vpc_id = requester_info['VpcId']
            pcx_attributes = {'requester_vpc_id': requester_vpc_id, 'status': peer.status}  # status is a dict
            network_object.add_node(peer.id, **pcx_attributes)
        else:
            # todo handle tihs correctly (effectively not handling now)
            print '*** attempting to add an already existing pcx: {}'.format(peer.id)

    # add "accepted" pcx'es
    for peer in vpc.accepted_vpc_peering_connections.all():
        if peer.id not in nodes:  # if the pcx ID is not a key in the nodes dict, i.e. doesn't yet exist, add it
            accepter_info = peer.accepter_vpc_info  # reduce the # of dict sub-references typed by hand
            accepter_vpc_id = accepter_info['VpcId']
            pcx_attributes = {'accepter_vpc_id': accepter_vpc_id, 'status': peer.status}  # status is a dict
            network_object.add_node(peer.id, **pcx_attributes)
        else:
            print '*** attempting to add an already existing pcx: {}'.format(peer.id)


def populate_router_data(vpc, network_obj):
    graph_data = network_obj.graph  # local ref to the graph-data dict of the graph object

    for rtb in vpc.route_tables.all():
        network_obj.add_node(rtb.id)  # add the route table to the graph/networkx object
        rtb_data = network_obj.node[rtb.id]  # short name for data dict assoc w/this route table
        rtb_data['assoc_subnets'] = []  # init assoc subnet list
        rtb_data['main'] = False  # init the flag indicating this rtb is main table for vpc

        for assoc in rtb.associations_attribute:  # gather associated subnets & determine if main
            subnet_id = assoc.get('SubnetId')  # None or subnet-id string
            main_flag = assoc.get('Main')  # if true this rtb is the "main" rtb for the vpc

            if not main_flag and subnet_id:  # this is an asoc'ed subnet, add the
                rtb_data['assoc_subnets'].append(subnet_id)
            elif main_flag and not subnet_id:  # this is the main rtb for this vpc
                rtb_data['main'] = True
                if not graph_data['main_route_table']:  # if main route table @ graph level is empty, set to curr value
                    graph_data['main_route_table'] = rtb.id
                elif graph_data['main_route_table'] == rtb.id:  # main rtb @ graph lvl set but curr rtb_id is same value
                    print '*** found more than one instance of the same route table indicated as main'
                else:  # we've found 2+ main route tables, which shouldn't be (?)
                    print '**** found two different main route tables: ' \
                          'previous: {}, curr: {}'.format(rtb.id, graph_data['main_route_table'])
            else:  # not main & no subnet OR main and subnet are nonsensical combo's alert (at least AFAIK)
                print '** Got strange association info.  ' \
                      'vpc: {}, rtb: {}, main flag: {}, subnet-id: {}'.format(vpc.id, rtb.id, main_flag, subnet_id)

            routes = rtb_data['routes'] = []

            for route in rtb.routes_attribute:
                dest_cidr = route.get('DestinationCidrBlock')
                dest_pfx = route.get('DestinationPrefixListId')
                gw_id = route.get('GatewayId')  # if this is local we don't care about it
                inst_id = route.get('InstanceId')
                pcx_id = route.get('VpcPeeringConnectionId')
                nat_gw = route.get('NatGatewayId')
                state = route.get('State')
                origin = route.get('Origin')
                egress_gw = route.get('EgressOnlyGatewayId')

                routes.append({'dest_cidr': dest_cidr, 'dest_pfx': dest_pfx,
                               'gw_id': gw_id, 'inst_id': inst_id,
                               'pcx_id': pcx_id, 'nat_gw': nat_gw,
                               'state': state, 'origin': origin,
                               'egress_gw': egress_gw})


def add_subnet_edges(network_obj):
    # add the explicitly associated subnets first, updating the assoc_route_table data item as you go
    nodes = network_obj.node  # local ref to dict of node data
    for curr_node in nodes:
        if get_node_type(curr_node) == 'router':  # only interested in router nodes
            rtb_id = curr_node
            subnets = nodes[curr_node]['assoc_subnets']
            if len(subnets):  # verify there are subnets in the list
                for subnet in subnets:
                    network_obj.add_edge(rtb_id, subnet)


def add_non_peer_conn_edges(network_obj):
    """
    add connections between route tables and gateway objects OTHER THAN VPC Peering Connections

    not adding the edges between router and pcx here b/c want to collect all pcx "instances" first, which requires
    looping over all the VPC's.  Put another way, pcx'es can be thought of as being "outside" any VPC so we can't add
    edges to them until we have all of them accounted for
    :param network_obj: a networkx graph object containing node data, i.e. topology data
    :return:
    """
    node_dict = network_obj.node

    for curr_node in node_dict:  # for ea node in nodes
        if get_node_type(curr_node) == 'router':  # if it's a router
            route_list = node_dict[curr_node]['routes']  # get its routes
            for route in route_list:
                gw_name = create_gateway_name(route)  # create a gw "name" from the route's gw/nh attributes
                if gw_name == 'local':
                    print '*** gw name is "local" - skipping'
                elif gw_name.startswith('pcx'):
                    print '*** not adding pcx edges in "add_other_edge" func'  # eventually just skip pcx'es
                elif gw_name not in node_dict:  # if the gw "name" is NOT in the node dict
                    # there's a problem, print an error and do nothing
                    print '*** Cannot add a new node to the network at this point: {}'.format(gw_name)
                else:  # else add an edge
                    network_obj.add_edge(curr_node, gw_name)  # +edge: current rtb and the gw (next hop)


def build_nets(networks, vpcs, aws_session=None):
    """
    populate networkx network object w/topology data and associated meta-data

    networkx network object <> aws VPC, each networkx network object contains topology data (subnets, routes, network
    "devices") as well as metadata including security group information

    :param networks: dict of networkx network objects
    :param vpcs: iterable of boto3 vpc objects
    :param aws_session: boto3 session object
    :return: n/a
    """

    # todo verify correct handling of VPN gateways
    # todo P3 get NACL's

    for vpc in vpcs:
        # vpc object info @: https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#vpc
        vpc_attribs = {'cidr': vpc.cidr_block, 'isdefault': vpc.is_default,
                       'state': vpc.state, 'main_route_table': None}  # collect node attributes

        network_obj = networks[vpc.id] = nx.Graph(vpc=vpc.id, **vpc_attribs)

        # need to pass networks dict to functions below because in at least one case (vpc peer connections) the network
        # to which a node must be added may not be the one used in this iteration of the for-loop
        # sec_groups = get_subnet_data(networks, vpc)
        get_subnet_data(networks, vpc)

        get_vpngw_data(networks, vpc, aws_session)  # find the vpn gw's and add to networkx graph

        get_inetgw_data(networks, vpc)  # find internet gw's and add to network

        get_nat_gateways(network_obj, vpc.id, aws_session)

        # run routers last as that function currently depends on the other nodes existing in order to
        # add edges - may also want to completely separate edge adds from node adds
        populate_router_data(vpc,
                             network_obj)  # add route tables to graph and add edges between rtb's, subnets, igw's & vgw's

        get_peering_conn_data(network_obj, vpc)

        add_subnet_edges(network_obj)

        add_non_peer_conn_edges(network_obj)

        # todo P1 handle other edges - e.g. to PCX's for sure and too ???


def lookup_sec_group_data(group_id, sg_data):
    # in the sec group, for now, enhance to return sg ID and name (possibly tags)

    group_name = [sg.group_name for sg in sg_data if sg.id == group_id][0]

    return group_name


def replace_negative_one_with_all(value):  # -1 represents 'ALL' in several places in boto3 data structures
    if value == '-1':
        return 'ALL'
    else:
        return value


def get_port_range(rule):
    """
    extract port range from a rule data dict

    :param rule: rule is the dict of data from the boto3.ec2.security_group.ip_permissions object
    :return: (start, end)  tuple or 'NA' (not applicable)
    """

    if 'FromPort' in rule.keys():
        start = replace_negative_one_with_all(rule['FromPort'])
        end = replace_negative_one_with_all(rule['ToPort'])
        port_range = (start, end)
    else:
        port_range = 'NA'

    return port_range


def get_source_ranges(rule):
    src_ranges = []  # gather srcs (curr aws allows only 1)

    for ip_range in rule['IpRanges']:  # ip ranges are list of dicts, which contain a single key 'cidrip'
        src_ranges.append(ip_range['CidrIp'])

    return src_ranges


def get_source_sec_groups(rule, sec_group_data_dict):
    """
    get a list of the security groups in the source "field" of the rule

    :param rule: a boto3.ec2.security_group.ip_permissions object (or ip_permissions_egress too)
    :param sec_group_data_dict: a dictionary containing relevant security group data points, indexed by group ID
    :return:
    """

    src_sec_groups = []  # gather (acct, sg_id) tuples, this is probably mutex with ip ranges

    if len(rule['UserIdGroupPairs']) > 0:

        for uid_group_pair in rule['UserIdGroupPairs']:
            group_id = uid_group_pair['GroupId']
            group_name = lookup_sec_group_data(group_id, sec_group_data_dict)
            user_id = uid_group_pair['UserId']
            src_sec_groups.append((user_id, group_id, group_name))

    return src_sec_groups


# todo refactor to take only sec_group_ID and sec_group data dict - b/c the permissions are already in the latter
def get_access_rules(sec_group_id, permission_list, sec_group_data_dict):  # helper func for build_subnet_rules
    """
    return data associated with access rules in an aws boto3.ec2.security_group.ip_pmissions (and egreess)

    NB: rule order does not matter in AWS SG ACL's b/c only permits are allowed

    :param sec_group_id: security group identifier (string)
    :param permission_list: boto3.ec2.security_group.ip_permissions (or ip_permissions_egress) data item
    from the security group identified by 'sec_group_id'
    :param sec_group_data_dict:
    :return: rules data structure containing all rules for a given sec group
    """
    extracted_rules = []  # list of rules, rule is a dict with sec_grp_id, sources, proto and port info

    for rule in permission_list:  # from boto3.ec2.SecurityGroup.ip_permissions[_egress], itself a list of dicts

        # get the proto name
        proto = replace_negative_one_with_all(rule['IpProtocol'])

        # get port range
        port_range = get_port_range(rule)

        # get the sources, which may be cidr blocks or security groups
        src_sec_groups = get_source_sec_groups(rule, sec_group_data_dict)

        src_ranges = get_source_ranges(rule)
        src_ranges.extend(src_sec_groups)  # this should end up containing cidr ranges or group info, not both

        extracted_rules.append({'sgid': sec_group_id, 'source': src_ranges, 'proto': proto,
                                'ports': port_range})

    return extracted_rules


def build_sec_group_rule_dict(sec_group_data):
    """
    extract pertinent info from aws security group rules

    :param sec_group_data: dict of aws security group data (direct from aws SDK)
    :return: dict of rules by security group and grouped by direction (inacl, outacl)
    """

    # temp holding place before assignment as attributes of networkx node representing a subnet
    sec_group_rule_dict = {}

    # prebuild a reformatted set of rules for the security group
    for sec_group in sec_group_data:
        sec_group_rule_dict[sec_group.id] = {}

        # get rules in more concise form & assign to new fields in sg_rules
        sec_group_rule_dict[sec_group.id]['inacl'] = get_access_rules(sec_group.id, sec_group.ip_permissions,
                                                                      sec_group_data)

        sec_group_rule_dict[sec_group.id]['outacl'] = get_access_rules(sec_group.id, sec_group.ip_permissions_egress,
                                                                       sec_group_data)

    return sec_group_rule_dict


def collect_subnet_rules(networks, sec_group_data):
    """
    extract security group rules for a subnet from instance data and insert into the appropriate networkx data fields

    Finds the security groups associated with a given subnet and for each it extracts the associated
    rules.  Those rules are formatted and added to the networkx graph as an attribute of the associated subnet

    :param networks: dictionary of networks, which are networkx graphs
    :param sec_group_data:  iterable of aws/boto3 security group objects
    :return: nothing
    """

    sg_rules = build_sec_group_rule_dict(sec_group_data)  # build the idict of rules, to be indexed by sec_group ID

    # for each subnet node in a network, loop over the security groups of that subnet and pull the rules from the
    # rules dict created above
    for network in networks.values():  # for each networkx graph object in dict called networks {net_name: netxobj}

        for node in network.nodes():  # loop over the graph's nodes

            if node.startswith('subnet'):  # only interested in subnet nodes, not internet gw's, etc.

                curr_node = network.node[node]  # unfortunate overloading of meaning of term 'node' here
                curr_node['inacl'] = []  # create empty lists in the network node dicts to accept acl info
                curr_node['outacl'] = []

                for sg_id in curr_node['sec_groups']:  # loop over set of sg's assoc. with this subnet
                    curr_node['inacl'].extend(sg_rules[sg_id]['inacl'])  # add sg inacl to subnet inacl
                    curr_node['outacl'].extend(sg_rules[sg_id]['outacl'])  # add sg inacl to subnet inacl


def render_gexf(networks, out_dir_string):
    """
    write out gephi file for each network in a dict of networks to a file
    :param networks: dict of networkx graphs
    :param out_dir_string: string representing the output directory path
    :return:
    """
    # todo fix output path with os.path methods

    for net_id, net_graph in networks.items():
        nx.write_gexf(net_graph, out_dir_string + net_id + '.gexf', prettyprint=True)


def render_pyplot(network, output_dir):
    netid = network.graph['vpc']
    output_dir = os.path.join(output_dir, netid)
    pos = nx.spring_layout(network, scale=10)
    nx.draw_networkx_nodes(network, pos=pos, with_lables=True, node_size=400, color='c', alpha=0.7, linewidths=None)
    nx.draw_networkx_labels(network, pos=pos, font_size=9)
    nx.draw_networkx_edges(network, pos)
    plot.title(netid)
    plot.axis('off')
    plot.tight_layout()
    plot.savefig(output_dir + netid)
    plot.clf()


def export_sgrules_to_csv(networks, outfile='rules.csv'):
    """
    Write security group rules to outfile formatted as csv

    Writes a single csv file with ea row a rule in the network.  Format can be obtained by looking at the header
    row defined in the function itself

    :param networks: dict of networkx network objects identified by vpc_id, e.g. {vpc-xxx: netxobj, ...}
    :param outfile: fully qualified path of output csv file
    :return: no return value
    """

    f = open(outfile, 'w')
    csvwriter = csv.writer(f, lineterminator='\n')

    csvwriter.writerow('vpc_id subnet_id sec_group_id direction rule_num sources protocol port_range'.split())

    for network_id, network_object in networks.items():

        for node, data in network_object.nodes_iter(data=True):  # get 2tuples of node, assoc data and loop over 'em
            if node.startswith('subnet'):  # if subnet, then get rules
                for acl in data['inacl']:  # inbound acl first
                    csvwriter.writerow([network_id, node, acl['sgid'], 'in', acl['source'], acl['proto'],
                                        acl['ports']])
                for acl in data['outacl']:  # inbound acl first
                    csvwriter.writerow([network_id, node, acl['sgid'], 'out', acl['source'], acl['proto'],
                                        acl['ports']])

    f.flush()
    f.close()


def render_nets(networks, graph_format=None, output_dir=None, yaml_export=False, csv_file=None):
    if graph_format:  # don't lower() if None (likely b/c format option not specified)
        graph_format = graph_format.lower()

    if not output_dir:  # use current directory if no output dir specified
        output_dir = os.path.curdir

    if not graph_format and yaml_export:  # no format specified, but yaml output requested (--export-to-yaml)
        for net_name, network in networks.iteritems():  # todo add code to actually export to yaml
            print net_name, ': '
            pp.pprint(network.graph)
            f = open(net_name, 'w')
            temp_dict = {}
            for n, d in network.nodes_iter(data=True):  # get tuples of node_name and assoc data dict for each node
                print n, ': '
                pp.pprint(d)
                print '\n'
            f.close()

    elif graph_format == 'print':
        if yaml_export:  # if the --export-to-yaml cli arg was included, save each nw to a yaml file
            for network in networks.values():
                pp.pprint(network)
                # add yaml export code
        else:  # --export-to-yaml was not included
            for network in networks.values():
                print network.nodes()

    elif graph_format == 'gephi':
        if yaml_export:
            for network in networks.values():
                render_gexf(network, output_dir)
                # add yaml export code
        else:
            for network in networks.values():
                render_gexf(network, output_dir)

    elif graph_format == 'pyplot':
        if yaml_export:
            for network in networks.values():
                render_pyplot(network, output_dir)
                # add yaml export code
        else:
            for network in networks.values():
                render_pyplot(network, output_dir)

    elif graph_format is not None:
        print 'unknown output format requested: ', graph_format

    if csv_file is not None:  # should be None if option not specified, otherwise it's a filename with opt. path

        # todo if keeping this feature, enhance it to handle "all" cases of path/filename that may be handed to it
        if os.path.split(csv_file)[0] == '':  # got file name only if path part is empty
            csv_file = os.path.join(output_dir, csv_file)  # save with other output files

        export_sgrules_to_csv(networks, outfile=csv_file)


def execute_rule_checks(networks):  # figure out what params to pass

    # load port names, which are "high risk" ports w/names from yaml file
    # create checks - possibly a function per check?
    # figure out a way to load checks from a file?

    f = open('ports.yaml')
    port_dict = yaml.load(f)
    f.close()

    # checks to execute:
    # rules with excessive range: any, or # hosts > T (t = configurable threshold)
    # rules with "high risk" ports
    # rules with large src or dst CIDR block
    #
