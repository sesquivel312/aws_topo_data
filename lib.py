"""

Todo:
    * Add a name key to all nodes in the network graph (currently only added to the route-table nodes)
    * update rendering functions to use node names rather than ID's

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
import os
import os.path
import yaml
import csv
import getpass
import sys
import logging
import pprint as pp

import pdb

import networkx as nx
import matplotlib.pyplot as plot

# todo add paginator to use of client ec2.client.describe_vpc_endpoints
# todo P3 try to get logging out of global in this module
# todo P3 decide on UTC or local TZ, then fix log message format accordingly
# todo P3 start using the functions built into logging that read config files
LOG_MSG_FORMAT_STRING = '%(asctime)s (HH:MM) TZN APP %(message)s'
LOG_TIMESTAMP_FORMAT_STRING = '%Y-%m-%d %H:%M:%S'

# filename='output/log_output.log'
logging.basicConfig(format=LOG_MSG_FORMAT_STRING,
                    datefmt=LOG_TIMESTAMP_FORMAT_STRING, filename='output/log_output.log', filemode='w')
logger = logging.getLogger('aws_topo')  # create our own logger to set log level independent of the global level
logger.setLevel(logging.INFO)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', help='AWS REGION to use, defaults to us-west-2', default='us-west-2')
    parser.add_argument('--graph-format', help='Graph output format; no graph output produced if not specified, options'
                                               ' include:\nprint, gephi, pyplot\nprint prints out the network info to'
                                               'the terminal')
    parser.add_argument('--output-dir', help='Path output is written to, current dir if not specified')
    parser.add_argument('--export-network-to-yaml', help='flag indicating network data should be exported to a YAML '
                                                         'file in the directory indicated by --output-dir (or current '
                                                         'directory if not specified', action='store_true')
    parser.add_argument('--csv-file', help='Export rules to csv formatted file named by the value to this argument')
    parser.add_argument('--log-file', help='Path of file to place log ouput, defaults to output.log')

    return parser.parse_args()


def get_aws_api_credentials():
    key_id = os.environ.get('AWS_ACCESS_KEY_ID')
    key = os.environ.get('AWS_SECRET_ACCESS_KEY')

    if not key_id:
        key_id = getpass.getpass('Enter key ID: ')
        os.environ['AWS_ACCESS_KEY_ID'] = key_id
    if not key:
        key = getpass.getpass('Enter key: ')
        os.environ['AWS_SECRET_ACCESS_KEY'] = key

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


def get_aws_object_tags(aws_object, tags_to_extract):
    """
    extract the values of a list of tags associated with an AWS object

    A lot of meta data is stored in AWS tags.  Generally they are found in the 'tags' attribute of aws objects that
    support them.  They are stored in an intesting way - rather than being straight dictionarys (or similar mapping
    type) they are stored as a list of dicts.  Each dict contains two keys, which are always called: 'Key', 'Value'.

        For example:

            tags = [{'Key': 'Name', 'Value': 'Foo'}]

            This example contains one tag, they 'key' for the tag is 'Name' and it's value is 'Foo'

    Here we search for any dicts in the tag list whose 'Key' matches one of the items in the tag_list.

    Examples:
        given some aws object called ```some_aws_instance``` with an associated tags attribute as show above...

            get_aws_object_tags(some_aws_instance, ['Name'])

            Will return {'Name': 'Foo'}

    Todo:
        * Enhance to support multiple instances of a given tag 'name' (Key)?
        * this function can probably be optimized a bit

    Args:
        aws_object:  Any boto3 object that has a "tags" attribute
        tags_to_extract (list): list of key names for which to extract values

    Returns (dict): results

    """

    aws_object_tags = aws_object.tags

    results = {}  # todo: can/should this be initialized form the tags_to_extract?

    for tag in tags_to_extract:

        for aws_tag in aws_object_tags:  # todo determine if this can be changed to dict comprehension?

            if aws_tag['Key'] == tag:
                results.setdefault(tag, aws_tag['Value'])

    return results


def get_aws_object_name(aws_object, dict_reference):
    """
    get the AWS object name and add it to the node data

    Args:
        aws_object (boto3 object): a boto3 object that has the 'tags' attribute containing a Key called 'Name'
        dict_reference (dict): this is a reference to dictionary somewhere in the 'node' sub-hierarchy of the data model

    Returns: None

    """

    tag_dict = get_aws_object_tags(aws_object, ['Name', ])

    if tag_dict['Name']:
        dict_reference['name'] = tag_dict['Name']
    else:
        dict_reference['name'] = route_table_id


def dump_network_data(networks, f):
    """
    write out the network meta data to a file

    Todo:
        * Determine if this stays given there is a render to file function (which is not completed)

    Args:
        networks (dictionary): dictionary of networkx.Graph, one per VPC
        f (file): a reference to a file open for writing

    Returns: None

    """

    for id, net in networks.iteritems():

        pp.pprint(net.node, f)

    f.write('========================\n\n')


def get_vpcs_and_secgroups(aws_session=None):  # todo validate region inherited from Session
    """
    Get the VPCs and security groups from the current AWS account

    Args:
        aws_session (boto3/Session):  A Session init'ed with API keys and region name

    Returns: vpcsCollection security_groupsCollection

    """

    # todo check for vpcs with 0 instances and filter them

    if not aws_session:
        sys.exit('*** No valid EC2 session available, aborting...')

    ec2_resource = aws_session.resource('ec2')

    vpcs = ec2_resource.vpcs.all()  # .all() returns an iterable of all VPC objects associated w/the aws VPC
    sec_groups = ec2_resource.security_groups.all()

    return vpcs, sec_groups


def get_node_type(node_name):
    """
    helper function returning a string indicating the type of a node based on the node's name/id

    Args:
        node_name (string):

    Returns: string indicating node type: inet_gw | peer_conn | router | subnet | vpn_gw | nat_gw

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
    construct and return a gateway "name" from a dict of route attributes

    AWS routes have a number of attributes associated w/them. For the moment I can't tell
    which are mutex w/which-others.  E.g. if there's a value in the vpc peer conn id field must
    the gw-id field be None.  Rather than try to figure that out I'll construct a name from the
    various attributes by contactenting the route-attribute values into a single string.  If
    things go well there will only ever be one string that makes up the resulting gateway-name.
    If they don't go well, then the name will be something strange like vpx-abc123:igw-def321.

    Currently skipping any ??? == 'local'

    Args:
        route_dict (dict): dictionary of route attributes - see function populate_router_data

    Returns (string): constructed gateway name

    """

    # get the non None values from the route attribute dict, that matter in identifying the gw "name"
    name_components = [v for k, v in route_dict.iteritems() if k in
                       ['gw_id', 'inst_id', 'pcx_id', 'nat_gw', 'egress_gw'] and v]

    return ':'.join(name_components)


def get_subnet_data(networks, vpc):
    """
    enumerate subnets in a given VPC, subsequently extract security groups (per subnet) and install in a dict of
    networkx network objects

    the attributes are taken from the list of possible attributes associated with boto3.Subnet class, EXCEPT the
    assoc_route_table attribute, which is inserted by this script to be able to trace back from a subnet ID to it's
    associated route table.  NB for subnets not explicitly associated with a route table this will remain None, which
    implies the subnet is implicitly associated with the main route table of the VPC

    Args:
        networks (dict of networkx.Graph): dict of Graphs to populate with data from AWS API
        vpc (boto3.Vpc): Vpc object used to get the data from AWS that will be inserted into the Graph object

    Returns: None

    """

    for subnet in vpc.subnets.all():  # from boto3 vpc subnets collection

        subnet_attribs = {'avail_zone': subnet.availability_zone, 'cidr': subnet.cidr_block,
                          'assign_publics': subnet.map_public_ip_on_launch, 'state': subnet.state,
                          'assoc_route_table': None}

        networks[vpc.id].add_node(subnet.id, **subnet_attribs)

        get_aws_object_name(subnet, networks[vpc.id].node[subnet.id])

        sec_group_set = set([])  # set of all security groups in this subnet

        # populate networkx network object with security groups
        for instance in subnet.instances.all():  # instance is a aws instance
            # get the security groups for this subnet
            # from the instances in it
            # todo P1 add NAT instances as network nodes - check source/dest-check instance proprty to identify natinst
            for group in instance.security_groups:
                sec_group_set.add(group['GroupId'])

        networks[vpc.id].node[subnet.id]['sec_groups'] = sec_group_set


def get_vpc_endpoint_data(network_obj, vpc_id, aws_session):
    """
    add all vpc endpoints in the VPC to the network graph


    :param network_obj (network Graph): the Graph object into which the vpce data will be placed
    :param vpc_id (string): id of the VPC from which to extract vpce data
    :param aws_session (boto3/Session): boto3 Session object initialized with API keys, region, etc.
    :return: None
    """

    ec2_client = aws_session.client('ec2')

    filter = [{'Name': 'vpc-id', 'Values': [vpc_id]}]

    ep_data = ec2_client.describe_vpc_endpoints(Filters=filter)
    ep_list = ep_data['VpcEndpoints']  # only need the list todo P2 address paging

    for ep in ep_list:
        ep_attribs = {'service_name': ep['ServiceName'], 'state': ep['State'], 'route_table_ids': ep['RouteTableIds']}
        network_obj.add_node(ep['VpcEndpointId'], attr_dict=ep_attribs)


def get_customer_gw_data():  # should this be outside the VPC loop, e.g. are these logically outside the vpc?
    pass


def get_vpn_connection_data():  # are these outside the VPC?
    pass


def get_vpn_gw_data(networks, vpc, aws_session):
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
    """
    add VPC peering connections to the node dict of the given networkx Graph

    :param network_object (networkx/Graph): Graph representing a VPC and it's topology
    :param vpc (boto3/Vpc): a VPC class instance (came from a VpcCollection)
    :return:
    """

    # todo determine how to represent multiple VPC's and the nodes w/in it - topo per account vs per vpc?
    # todo P2 verify collecting both accepter and requester vpc-id's and not overwriting data (check netwokx doco)


    nodes = network_object.node

    # add pcx'es whose initial request originated in THIS vpc
    for peer in vpc.requested_vpc_peering_connections.all():
        if peer.id not in nodes:  # if the pcx isn't already a node in the nodes dict
            requester_info = peer.requester_vpc_info  # this just reduces some typing later
            requester_vpc_id = requester_info['VpcId']
            pcx_attributes = {'requester_vpc_id': requester_vpc_id, 'status': peer.status}  # status is a dict
            network_object.add_node(peer.id, **pcx_attributes)
        else:
            # todo handle this correctly (effectively not handling now)
            logger.info('*** attempting to add an already existing pcx: {}'.format(peer.id))

    # add pcx'es whose initial request was originated in some OTHER vpc
    for peer in vpc.accepted_vpc_peering_connections.all():
        if peer.id not in nodes:  # if the pcx ID is not a key in the nodes dict, i.e. doesn't yet exist, add it
            accepter_info = peer.accepter_vpc_info  # eliminates a bit of typing
            accepter_vpc_id = accepter_info['VpcId']
            pcx_attributes = {'accepter_vpc_id': accepter_vpc_id, 'status': peer.status}  # status is a dict
            network_object.add_node(peer.id, **pcx_attributes)
        else:
            logger.info('*** attempting to add an already existing pcx: {}'.format(peer.id))


def add_route_table_node(network, route_table):
    """
    add the route-table node type to the network graph

    Also extracts the AWS RouteTable name from the tags attribute and adds that data

    Args:
        network (networkx.Graph): graph representing the VPC topo and holding assocaited meta-data
        route_table (boto3.RouteTable): the route table to add to network graph

    Returns: None

    """

    # setup local variables
    route_table_id = route_table.id

    # add "routers" to the graph (AWS route tables)
    network.add_node(route_table_id)

    get_aws_object_name(route_table, network.node[route_table_id])


def get_route_table_subnet_associations(network, vpc, route_table):
    """
    collect subnet ID's explicitly associated with a given RouteTable and add them to the network data model

    Deals with *explicitly* associated subnets only (i.e. associated at creation time).

    Also identifies the main route table for the given Vpc.  The main route table is identified a bit circuitously.
    Each RouteTable has an associations_attribute, which is mostly a list of explicitly associated subnets that are
    provided as a dictionary of pertinent data fields.  The 'Main' key in that dict is a boolean that will be set (True)
    when the route table to which this association is attached is the main route table for the VPC.  In that case, the
    'SubnetId' field will be None (or perhaps it doesn't exist?).  Because of this, we check for various combinations of
    'Main' and 'SubnetId' that (probably) should not happen, e.g. duplicate main subnets with the same subnet-id or,
    worse, two different subnets claiming to be main.

    Todo:
        * determine if get_subresources might be useful to get the implicitly associated subnets

    Args:
        route_table (boto3.RouteTable):
        network (networkx.Graph):
        vpc (boto3.Vpc):

    Returns: None

    """

    # set up some local and/or more obvious variable/object names
    route_table_id = route_table.id
    vpc_id = vpc.id
    network_data_dict = network.graph
    route_table_data_dict = network.node[route_table_id]

    # add associated subnet list to the route table data, associated means *explicitly* configured via AWS API calls
    route_table_data_dict['assoc_subnets'] = []

    # add and init the flag indicating if this is the main route table for this vpc
    # starts False, changed to True when the main route table is found
    route_table_data_dict['main'] = False

    for assoc in route_table.associations_attribute:

        subnet_id = assoc.get('SubnetId')
        main_flag = assoc.get('Main')

        if not main_flag and subnet_id:  # this is an asoc'ed subnet, add the
            route_table_data_dict['assoc_subnets'].append(subnet_id)

        elif main_flag and not subnet_id:  # this is the main rtb for this vpc
            route_table_data_dict['main'] = True

            # found 'the' main route table - check for possible error situations, such as two main route tables
            # if the id of the main route-table hasn't been set at the network (Graph) level yet, then set it
            if not network_data_dict['main_route_table']:
                network_data_dict['main_route_table'] = route_table_id

            # found another route table claiming to be main *with the same ID* as one found previously
            # I believe this should not occur so logging it if it does
            elif network_data_dict['main_route_table'] == route_table_id:  # found another, matching "main" rtb
                logger.info('Found main route table multiple times, which should probably not occur.  '
                            'vpc: {}, rtb: {}'.format(vpc_id, route_table_id))

            # another route table, with a different ID, is claiming to be main
            # this definitely shouldn't happen
            else:
                logger.info('Found two different main route tables: '
                            'vpc: {}, prev rtb-id: {}, '
                            'curr rtb-id: {}'.format(vpc_id, route_table_id,
                                                     network_data_dict['main_route_table']))

        # not main & no subnet OR main and subnet are nonsensical combo's alert (at least AFAIK)
        else:
            logger.info('Found possibly malformed subnet association data.  '
                        'vpc: {}, rtb: {}, main flag: {}, subnet-id: {}'.format(vpc_id, route_table_id, main_flag,
                                                                                subnet_id))


def get_route_table_routes(network, route_table):
    """
    collect the actual route data from a given route table and insert it into the network data model

    A 'route' is what is classically thought of when one says, "what's the route to network N" (in the context of the
    IP protocol).  This function gets the data associated with each route, e.g. destination and next hop, and puts that
    into the network data model.

    In the context of AWS a destination can be more than a prefix, it can also be a prefix list.  The latter is used
    when the next hop is an EC2 VPC endpoint.

    The next hop (NH) for a route is handled by several different attributes of a Route object.  I am not certain, but
    I believe these fields are mutually exclusive, i.e. only one can be something other than None.  For example, if the
    NH is a NAT gateway, then the nat_gateway_id attribute will be populated w/the NAT gateway's ID and all the other
    fields that could indicate a NH will be set to None.  The gateway_id attribute will contain a value in at least
    two instances, when the NH is an internet gateway and when it references the local subnet - i.e. the CIDR block
    associated with the VPC containing the route table of which this route is a member.

    Notes:
        InstanceId (aka instance_id) has a value other than None when the NH is a NAT instance, rather than a NAT
        gateway

    Args:
        network (networkx.Graph): Graph representing a given VPC
        route_table (boto3.RouteTable): route table from which to extract routes

    Returns: None

    """

    # set up some local and/or more obvious variable/object names
    route_table_data_dict = network.node[route_table.id]

    # create and init the route data list associated with this route table
    routes = route_table_data_dict['routes'] = []

    for route in route_table.routes_attribute:
        # dest network info
        dest_cidr = route.get('DestinationCidrBlock')
        dest_pfx = route.get('DestinationPrefixListId')  # used when NH is vpc endpoint (only?)

        # next hop data - these may be mutually exclusive - i.e. for ea. route, only one the NH fields can be
        # set to a string value - the rest should be None (to be confirmed)
        gw_id = route.get('GatewayId')  #
        inst_id = route.get('InstanceId')
        pcx_id = route.get('VpcPeeringConnectionId')
        nat_gw = route.get('NatGatewayId')
        egress_gw = route.get('EgressOnlyGatewayId')

        # route meta data
        state = route.get('State')
        origin = route.get('Origin')  # how route

        routes.append({'dest_cidr': dest_cidr, 'dest_pfx': dest_pfx,
                       'gw_id': gw_id, 'inst_id': inst_id,
                       'pcx_id': pcx_id, 'nat_gw': nat_gw,
                       'state': state, 'origin': origin,
                       'egress_gw': egress_gw})


def get_router_data(network, vpc):
    """
    Extract route table data for a given VPC and populate the network data model

    Relies on other functions to do mos of the real work.  This function is here to make the code
    a bit more readable (hopefully)

    Args:
        vpc (boto3.Vpc):
        network (networkx.Graph):

    Returns: None

    """

    for route_table in vpc.route_tables.all():

        add_route_table_node(network, route_table)

        # get the subnet associations data object from AWS API and iterate over it to extract useful info
        get_route_table_subnet_associations(network, vpc, route_table)

        # add the routes contained in this route table to our data model
        get_route_table_routes(network, route_table)


def add_explicit_subnet_edges(network_obj):
    """
    add edges between route-tables and subnets that are explicitly associated

    NB: subnets in AWS that are not configured with an association are implicitly associated w/the main route table

    Args:
        network_obj (networkx.Graph): Network representing the VPC containing the subnets to which edges will be added

    Returns: None

    """
    # add the explicitly associated subnets first, updating the assoc_route_table data item as you go
    node_dict = network_obj.node  # local ref to dict of node data

    for cur_node in node_dict:
        if get_node_type(cur_node) == 'router':  # only interested in router nodes
            rtb_id = cur_node
            subnets = node_dict[cur_node]['assoc_subnets']
            if len(subnets):  # verify there are subnets in the list
                for subnet in subnets:
                    network_obj.add_edge(rtb_id, subnet)


def add_non_peer_conn_edges(network_obj):
    """
    add connections for node types OTHER THAN vpce's (vpc endpoints)

    Currently not sure this is covering all possible node types

    Also, seem to have lost notes indicating why vpce's can't be handled here.  recall it was to do w/having to visit
    all the VPC's first - in order to get all the vpce data so trying to add edges first caused dictionaries to be
    changed while they were being iterated over - which is bad

    Works by iterating over the nodes and checking their type.  When a route table (aka "router") is found, iterate
    over it's routes, grabbing the next hop information.  For NH's other than VPCE's, add an edge for them

    Args:
        network_obj (networkx Graph): a Graph object from which to extract route data

    Returns: None

    """

    node_dict = network_obj.node

    for cur_node in node_dict:
        if get_node_type(cur_node) == 'router':  # if it's a router

            route_list = node_dict[cur_node].get('routes')  # get the list of routes assoc w/this route-table

            if not route_list:
                logger.info('Skipping route table {}, contains no routes'.format(cur_node))
                continue

            for route in route_list:

                gw_name = create_gateway_name(route)

                if gw_name.startswith('pcx'):
                    logger.info(
                        'got a pcx next hop, not handled by this function (add_non_peer_conn_edges)')  # eventually just skip pcx'es

                # local is the route for the CIDR block attacked to the VPC itself, seems somethign like a hold down
                elif gw_name == 'local':
                    logger.info('got node type/name "local" - not handled at all, skipping')

                elif gw_name not in node_dict:  # if the gw "name" is NOT in the node dict
                    # there's a problem, print an error and do nothing
                    logger.info('{} is a next hop type that does not yet exist as a node in the network, '
                                'this should not occur, something has gone wrong'.format(gw_name))

                else:  # else add an edge
                    network_obj.add_edge(cur_node, gw_name)  # +edge: current rtb and the gw (next hop)


def build_nets(networks, vpcs, aws_session=None):
    """
    populate networkx network object w/topology data and associated meta-data

    networkx network object per aws VPC, each networkx network object contains topology data (subnets, routes, network
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

        vpcid = vpc.id
        network_obj = networks[vpc.id] = nx.Graph(vpc=vpc.id, **vpc_attribs)

        # need to pass networks dict to functions below because in at least one case (vpc peer connections) the network
        # to which a node must be added may not be the one used in this iteration of the for-loop
        # sec_groups = get_subnet_data(networks, vpc)
        get_subnet_data(networks, vpc)

        get_vpc_endpoint_data(network_obj, vpcid, aws_session)

        get_customer_gw_data()  # should this be outside the VPC loop, e.g. are these logically outside the vpc?

        get_vpn_gw_data(networks, vpc, aws_session)  # find the vpn gw's and add to networkx graph

        get_vpn_connection_data()  # are these outside the VPC?

        get_inetgw_data(networks, vpc)  # find internet gw's and add to network

        get_nat_gateways(network_obj, vpc.id, aws_session)

        # handle routers last as the function retrieving router data currently depends on the existence of all the other
        # node types
        # add edges - may also want to completely separate edge adds from node adds
        # add route tbls to graph & edges between rtb's, subnets, igw's & vgw's
        get_router_data(network_obj, vpc)

        get_peering_conn_data(network_obj, vpc)

        add_explicit_subnet_edges(network_obj)

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


def prepare_nodes(network):
    """
    This function will loop over the nodes, examine them to determine what color and other attributes should
    be associated with them and return that information


    Args:
        network (networkx/Graph): Graph object containing nodes to prepare

    Returns (???) : not sure what the return type will be - probably a dict which mapsa list of nodes to a a
    dict of attributes required to render them

    """
    pass


def render_pyplot(network, output_dir):
    netid = network.graph['vpc']
    output_dir = os.path.join(output_dir, netid)
    pos = nx.spring_layout(network, scale=10)
    prepare_nodes(network.node)
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
