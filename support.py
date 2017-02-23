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
                                                         'directory if not specified',action='store_true')
    parser.add_argument('--csv-file', help='Export rules to csv formatted file named by the value to this '
                                                       'argument')

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
    :return: node_type: string = inet_gw | peer_conn | router | subnet | vpn_gw |
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
    else:
        return None


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
        # todo: research using .get() method to access avail zone and avoid exception
        vpngw_attributes = {'id': vpngw['VpnGatewayId'], 'state': vpngw['State']}  # want avail zone, but not always
        #                                                                            returned
        networks[vpc.id].add_node(vpngw['VpnGatewayId'], **vpngw_attributes)


def get_inetgw_data(networks, vpc):
    for gateway in vpc.internet_gateways.all():
        networks[vpc.id].add_node(gateway.id)


def get_peering_conn_data(networks, vpc):  # get vpc peering connections
    # todo determine how to represent multiple VPC's and the nodes w/in it

    for peer_conn in vpc.accepted_vpc_peering_connections.all():
        accepter = peer_conn.accepter_vpc_info['VpcId']
        requester = peer_conn.requester_vpc_info['VpcId']
        pcx_attributes = {'id': peer_conn.id, 'accepter_vpc_id': accepter,
                          'requester_vpc_id': requester}
        if requester in networks.keys():  # if the vpc exists in the networks dict
            networks[requester].add_node(peer_conn.id, **pcx_attributes)
        else:  # create vpc first if it doesn't already exist
            networks[requester] = nx.Graph(vpc=requester)
            networks[requester].add_node(peer_conn.id, **pcx_attributes)
        if accepter not in networks.keys():  # similar for accepter end but assumed doesn't exist yet
            # logic reversed b/c I assume the requester is this VPC so graph probably exists, but
            # accepter graph may not yet have been created, I could put them int he same order w/the same logic
            # but the idea is this may be faster(?)
            networks[accepter] = nx.Graph(vpc=accepter)
            networks[accepter].add_node(peer_conn.id, **pcx_attributes)
        else:
            networks[accepter].add_node(peer_conn.id, **pcx_attributes)


def get_router_data2(networks, vpc):  # todo this is the old version, remove when reactor complete
    """
    collect route data & add edges based on them

    :param networks: dict of networkx graph objects - identified by vpc-id
    :param vpc: boto3.ec2.vpc object (one, not an iterable of many)
    :return:
    """

    # todo p1 adding edges for subnets assoc'd with main rtb to other rtbs, which isn't supposed to happen

    network_obj = networks[vpc.id]  # local ref to networkx graph object
    graph_data = network_obj.graph  # local ref to the graph-data dict of the graph object
    network_node_data = network_obj.node  # local ref to node-data dict of graph object

    # for each route table in the network/vpc
        # collect the following data:
        # id

        # for each assoc in the curr route table


    for route_table in vpc.route_tables.all():

        curr_rtb_id = route_table.id
        network_obj.add_node(curr_rtb_id)  # add route table node

        for assoc in route_table.associations_attribute:  # the association list contains the associated subnets
            # todo: need to ensure I'm getting the right subnets

            if assoc['Main']:  # this is the main RTB for this VPC
                # check to see if the main RTB has been set before
                # if not, set it
                if not graph_data['main_route_table']:
                    # graph_data['main_route_table'] = curr_rtb_id
                    graph_data['main_route_table'] = curr_rtb_id
                else:  # it was, alert and exit
                    sys.exit('*** Found a second route table marked main. '
                             'Previous: {}, Second: {}'.format(graph_data['main_route_table'], curr_rtb_id))

            # if there's a subnet, add edge between the subnet and router,
            # and update it's data to reflect that it's associated w/a rtb
            snid = assoc.get('SubnetId')  # association for main will not return a subnet id

            if snid:
                network_obj.add_edge(curr_rtb_id, snid)
                network_node_data[snid]['assoc_route_table'] = curr_rtb_id

        # find all the subnets associated with the main route table
        # first, loop over nodes in network data dict
        for curr_node, curr_data in network_node_data.items():
            if curr_node.startswith('subnet'):  # pick out the subnet nodes
                if not curr_data['assoc_route_table']:  # when None this subnet is assoc implicitly with vpc main rtb
                    # udpate it's 'assoc_route_table' to match reality
                    curr_data['assoc_route_table'] = graph_data['main_route_table']
                    network_obj.add_edge(curr_node, graph_data['main_route_table'])

        # find the various route target objects in this table and
        # add edge between route table & target
        for route in route_table.routes:
            if route.gateway_id:  # more than one type and, I believe, they are mutex with other "gateway" like objects
                if route.gateway_id.startswith('igw-'):  # got an internet gw
                    network_obj.add_edge(curr_rtb_id, route.gateway_id)
                elif route.gateway_id.startswith('vgw-'):  # got a vpn gateway
                    network_obj.add_edge(curr_rtb_id, route.gateway_id)
            if route.vpc_peering_connection_id:  # find the vpc peering connections
                network_obj.add_edge(curr_rtb_id, route.vpc_peering_connection_id)


def populate_router_data(vpc, network_obj):

    graph_data = network_obj.graph  # local ref to the graph-data dict of the graph object

    for rtb in vpc.route_tables.all():
        network_obj.add_node(rtb.id)  # add the route table to the graph/networkx object
        rtb_data = network_obj.node[rtb.id]  # short name for data dict assoc w/this route table
        rtb_data['assoc_subnets'] = []  # init assoc subnet list
        rtb_data['main'] = False  # init the flag indicating this rtb is main table for vpc

        for assoc in rtb.associations_attribute:  #gather associated subnets & determine if main
            subnet_id = assoc.get('SubnetId')  # None or subnet-id string
            main_flag = assoc.get('Main')  # if true this rtb is the "main" rtb for the vpc

            if not main_flag and subnet_id:  # this is an asoc'ed subnet, add the
                rtb_data['assoc_subnets'].append(subnet_id)
            elif main_flag and not subnet_id: # this is the main rtb for this vpc
                rtb_data['main'] = True
                if not graph_data['main_route_table']:  # if main route table @ graph level is empty, set to curr value
                    graph_data['main_route_table'] = rtb.id
                elif graph_data['main_route_table'] == rtb.id:  # main rtb @ graph lvl set but curr rtb_id is same value
                    print '*** found more than one instance of the same route table indicated as main'
                else:  # we've found 2+ main route tables, which shouldn't be (?)
                    print '**** found two different main route tables: ' \
                          'previous: {}, curr: {}'.format(rtb.id, graph_data['main_route_table'])
            else:  #  not main & no subnet OR main and subnet are nonsensical combo's alert (at least AFAIK)
                print '** Got strange association info.  ' \
                      'vpc: {}, rtb: {}, main flag: {}, subnet-id: {}'.format(vpc.id, rtb.id, main_flag, subnet_id)

            routes = rtb_data['routes'] = []

            for route in rtb.routes_attribute:
                dest_cidr = route.get('DestinationCidrBlock')
                dest_pfx = route.get('DestinationPrefixListId')
                gw_id = route.get('GatewayId') # if this is local we don't care about it
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


def populate_subnet_edges(network_obj):
    # add the explicitly associated subnets first, updating the assoc_route_table data item as you go
    nodes = network_obj.node  # local ref to dict of node data
    for curr_node in nodes:
        if curr_node.startswith('rtb-'):  # only interested in router nodes
            rtb_id = curr_node
            subnets = nodes[curr_node]['assoc_subnets']
            if len(subnets):  # verify there are subnets in the list
                for subnet in subnets:
                    network_obj.add_edge(rtb_id, subnet)


def populate_other_edges(network_obj):
    nodes = network_obj.node

    # todo P1 start below
    # I am still working through handling the routing data
    # it should probably be separated completely rather than putting a bunch of helper fuctions into the
    # get_router_data method

    # for ea node in nodes
        # if it's a route table then
            # for each route in it's route list
                # add an edge between the current route table and the route's gw-type
                # right now I can only process some types of gateways - i.e. igw, vgw, pcx
                # need to add handling for natgws, nat-instances, egress-only-igw's
                # also detemrine what a "destination prefix list is" - something to do w/an AWS service?



    # for route in route_table.routes:
    #     if route.gateway_id:  # more than one type and, I believe, they are mutex with other "gateway" like objects
    #         if route.gateway_id.startswith('igw-'):  # got an internet gw
    #             network_obj.add_edge(curr_rtb_id, route.gateway_id)
    #         elif route.gateway_id.startswith('vgw-'):  # got a vpn gateway
    #             network_obj.add_edge(curr_rtb_id, route.gateway_id)
    #     if route.vpc_peering_connection_id:  # find the vpc peering connections
    #         network_obj.add_edge(curr_rtb_id, route.vpc_peering_connection_id)


def get_router_data(networks, vpc):
    """
    collect route data & add edges based on them

    :param networks: dict of networkx graph objects - identified by vpc-id
    :param vpc: boto3.ec2.vpc object (one, not an iterable of many)
    :return:
    """

    network_obj = networks[vpc.id]  # local ref to networkx graph object

    populate_router_data(vpc, network_obj)  # add data about route tables first (use this for edge finding, etc.)

    # loop over router associations e.g. connected subnets and add edges as needed
    populate_subnet_edges(network_obj)

    # loop over routes in route tables and add edges as appropriate (e.g. igw, pcx. etc)
    populate_other_edges(network_obj)


def build_nets(networks, vpcs, aws_session=None):
    """
    populate networkx network object w/topology data and associated meta-data

    networkx network object <> aws VPC, each networkx network object contains topology data (subnets, routes, network
    "devices") as well as metadata including security group information

    :param networks: dict of networkx network objects
    :param vpcs: iterable of boto3 vpc objects
    :return: n/a
    """

    # todo verify correct handling of VPN gateways
    # todo get NACL's

    for vpc in vpcs:

        # vpc object info @: https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#vpc
        # todo add tags to attributes - but be ware of how they are handled by ??? networkx, or maybe something else?
        vpc_attribs = {'cidr': vpc.cidr_block, 'isdefault': vpc.is_default,
                       'state': vpc.state, 'main_route_table': None}  # collect node attributes

        networks[vpc.id] = nx.Graph(vpc=vpc.id, **vpc_attribs)

        # need to pass networks dict to functions below because in at least one case (vpc peer connections) the network
        # to which a node must be added may not be the one used in this iteration of the for-loop
        # sec_groups = get_subnet_data(networks, vpc)
        get_subnet_data(networks, vpc)

        get_vpngw_data(networks, vpc, aws_session)  # find the vpn gw's and add to networkx graph

        get_inetgw_data(networks, vpc)  # find internet gw's and add to network

        get_peering_conn_data(networks, vpc)

        # run routers last as that function currently depends on the other nodes existing in order to
        # add edges - may also want to completely separate edge adds from node adds
        get_router_data(networks, vpc)  # add route tables to graph and add edges between rtb's, subnets, igw's & vgw's


# todo also collect network acl data
def lookup_sec_group_data(group_id, sg_data):

    # todo lookup some sec group data - this may be a pia as the most interesting group contents are the instances
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
    # todo refactor to take only sec_group_ID and sec_group data dict - b/c the permissions are already in the latter
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
