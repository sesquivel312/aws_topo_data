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
import os
import os.path
import yaml
import csv
import getpass
import sys
import logging
import pprint as pp

import pdb

import netaddr
import networkx as nx
import matplotlib.pyplot as plot

# todo P1 identify that ELB's exist
# todo P1 identify that WAF/Shield is configured
# todo P1 add paginator to use of client ec2.client.describe_vpc_endpoints
# todo P2 run port checks on ELB listener ports
# todo P2 when ELB listener = 443, verify ciphers are configured at all AND check for weak ciphers (2 diff checks)
# todo P2 add support for Direct Connect (similar to VPN)
# todo P2 add full LB support
# todo P2 add full WAF & sheild support
# todo P2 Add a name key to all nodes in the network graph (currently only added to the route-table nodes)
# todo P2 update rendering functions to use node names rather than ID's\
# todo P3 optimize data collection - e.g. currently looping network nodes multiple times to add edges of diff types
# todo P3 try to get logging out of global in this module
# todo P3 decide on UTC or local TZ, then fix log message format accordingly
# todo P3 start using the functions built into logging that read config files
# todo P3 logging - generally improve - in particular how it's 'shared' between the driver script and this module
# todo P3 logging - factor logging setup out of global name space and make configurable via CLI and file
# todo P3 generalize this away from AWS specifically
# todo P3 logging - factor out logging in each function to a utility function so calls w/in functions are "the same"?
# todo P3 include which risky ports were identified in a port range
# todo add geo and/or black/white-list IP range/address checks - i.e. check lists supplied by EW or 3rd parties
# todo IAM audit
# todo Terraform Audit, this is mostly a separate function, but could be combined to "Diff" the to-be and as-is configs
# todo Route 53 audit, minimum is keep record of domains configured and diff from previous run - research other checks
# todo add alert logic to topo and rules checks - will require research
# todo add mod-security to topo and rule checks - will require research



LOG_MSG_FORMAT_STRING = '%(asctime)s (HH:MM) TZN APP %(message)s'
LOG_TIMESTAMP_FORMAT_STRING = '%Y-%m-%d %H:%M:%S'

# filename='output/log_output.log'
logging.basicConfig(format=LOG_MSG_FORMAT_STRING,
                    datefmt=LOG_TIMESTAMP_FORMAT_STRING, filename='output/log_output.log', filemode='w')
logger = logging.getLogger('aws_topo')  # create our own logger to set log level independent of the global level
logger.setLevel(logging.INFO)


def load_yaml_file(file_name):
    """
    load a yaml file into a dict and return it

    Args:
        file_name (string): name of file to load to dict

    Returns:

    """

    with open(file_name) as f:
        pydict = yaml.load(f)
        return pydict


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
    parser.add_argument('--export-rules', help='Export rules to csv formatted file named by the value to this argument')
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


def get_specific_aws_tags(aws_tags, tags_to_extract):
    """
    extract the values of a list of tags associated with an AWS object from a "prepared" list of tags

    A lot of meta data is stored in AWS tags.  Generally they are found in the 'tags' attribute of aws objects that
    support them.  They are stored in an intesting way - rather than being straight dictionarys (or similar mapping
    type) they are stored as a list of dicts.  Each dict contains two keys, which are always called: 'Key', 'Value'.

        For example:

            tags = [{'Key': 'Name', 'Value': 'Foo'}]

            This example contains one tag, they 'key' for the tag is 'Name' and it's value is 'Foo'

    Here we search for any dicts in the tag list whose 'Key' matches one of the items in the tag_list.

    NB: this function assumes you already pulled the tags from AWS somehow, either as a boto3 object attribute (tags)
    or from the output of a lower level function.

    Examples:
        given the tag list above

            get_specific_aws_tags(some_aws_instance, ['Name'])

        Will return {'Name': 'Foo'}

    Todo:
        * Enhance to support multiple instances of a given tag 'name' (Key)?
        * this function can probably be optimized a bit

    Args:
        aws_tags (list of dicts):  list of tags in the "standard" aws format
        tags_to_extract (list): list of key names for which to extract values

    Returns (dict): results

    """

    results = {}  # todo: can/should this be initialized from the tags_to_extract?

    for tag in tags_to_extract:

        for aws_tag in aws_tags:  # todo determine if this can be changed to dict comprehension?

            if aws_tag['Key'] == tag:
                results.setdefault(tag, aws_tag['Value'])

    return results


def get_aws_object_name(aws_tags):
    """
    the name associated with an AWS object from a list of tags from AWS

    NB: assumes the typical AWS tags format for boto3

    Args:
        aws_tags (list(dicts)): tags and associated values, typically from <object>.tags

    Returns (string): the objects name (from tags)

    """

    try:
        tag_dict = get_specific_aws_tags(aws_tags, ['Name', ])  # todo P3 add exception handling elsewhere
    except TypeError as e:
        return 'NAME_NOT_EXIST'

    return tag_dict.get('Name', 'NAME_NOT_EXIST')


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

    for net_id, net in networks.iteritems():
        f.write('======= Dumping VPC: {} =======\n'.format(net.graph['vpc']))
        f.write('== VPC Level Data ==\n')
        pp.pprint(net.graph, f)
        f.write('== Node Data ==\n')
        pp.pprint(net.node, f)
        f.write('\n\n')


# todo P3 validate region inherited from Session
# todo P3 separate get vpcs from get sec-groups
def get_vpcs_and_secgroups(session=None):
    """
    Get the VPCs and security groups from the current AWS account

    Args:
        session (boto3/Session):  A Session init'ed with API keys and region name

    Returns: vpcsCollection security_groupsCollection

    """

    # todo check for vpcs with 0 instances and filter them

    if not session:
        sys.exit('*** No valid EC2 session available, aborting...')

    ec2_resource = session.resource('ec2')

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


def create_gateway_name(route):
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
        route (dict): dictionary of route attributes - see data-model.txt for more info

    Returns (string): constructed gateway name

    """

    # get the non None values from the route attribute dict, that matter in identifying the gw "name"
    node_type_prefixes = ['gw_id', 'inst_id', 'pcx_id', 'nat_gw', 'egress_gw']

    name_components = [v for k, v in route.iteritems() if k in
                       node_type_prefixes and v]

    return ':'.join(name_components)


def get_subnets(networks, vpc):
    """
    enumerate subnets in a given VPC, subsequently extract security groups (per subnet) and install in a dict of
    networkx network objects

    the attributes are taken from the list of possible attributes associated with boto3.Subnet class, EXCEPT the
    assoc_route_table attribute, which is inserted by this script to be able to trace back from a subnet ID to it's
    associated route table.  NB for subnets not explicitly associated with a route table this will remain None, which
    implies the subnet is implicitly associated with the main route table of the VPC.  Regardless the
    assoc_route_table key is only created here, it's final value will be udpated by the functions that add route-tables

    Args:
        networks (dict of networkx.Graph): dict of Graphs to populate with data from AWS API
        vpc (boto3.Vpc): Vpc object used to get the data from AWS that will be inserted into the Graph object

    Returns: None

    """

    for subnet in vpc.subnets.all():  # from boto3 vpc subnets collection

        subnet_name = get_aws_object_name(subnet.tags)
        subnet_attribs = {'name': subnet_name, 'avail_zone': subnet.availability_zone, 'default': subnet.default_for_az,
                          'cidr': subnet.cidr_block, 'assign_publics': subnet.map_public_ip_on_launch,
                          'state': subnet.state, 'assoc_route_table': None}

        networks[vpc.id].add_node(subnet.id, **subnet_attribs)
        logger.info('Added node {} to vpc {}'.format(subnet.id, vpc.id))

        sec_group_set = set([])  # set of all security groups in this subnet

        # populate networkx network object with security groups
        for instance in subnet.instances.all():  # instance is a aws instance
            # get the security groups for this subnet
            # from the instances in it
            # todo P1 add NAT instances as network nodes - check source/dest-check instance proprty to identify natinst
            for group in instance.security_groups:
                sec_group_set.add(group['GroupId'])
                logger.info('Added security-group {} to subnet {}'.format(group['GroupId'], subnet.id))

        networks[vpc.id].node[subnet.id]['sec_groups'] = sec_group_set


def get_vpc_endpoint_data(network, vpc, aws_session):
    """
    add all vpc endpoints in the VPC to the network graph

    Args:
        network (networkx.Graph): Graph into which vpce data for a given VPC will be placed
        vpc (boto3.Vpc): the relevant AWS VPC
        aws_session (boto3.Session): session object initialized with api keys, region, etc.

    Returns:None

    """

    ec2_client = aws_session.client('ec2')

    filter = [{'Name': 'vpc-id', 'Values': [vpc.id]}]

    ep_data = ec2_client.describe_vpc_endpoints(Filters=filter)
    ep_list = ep_data['VpcEndpoints']  # only need the list todo P2 address paging

    for ep in ep_list:
        ep_attribs = {'service_name': ep['ServiceName'], 'state': ep['State'], 'route_table_ids': ep['RouteTableIds']}
        network.add_node(ep['VpcEndpointId'], attr_dict=ep_attribs)
        logger.info('Added node {} to vpc: {}'.format(ep, vpc.id))


def get_customer_gw_data():  # should this be outside the VPC loop, e.g. are these logically outside the vpc?
    # todo P2 determine if we need customer gateway data, add code to handle if so
    pass


def get_vpn_connection_data():  # are these outside the VPC?
    # todo P2 determine if we need to handle vpn connections, add code to handle if yes
    pass


def get_vpn_gw_data(networks, vpc, session):
    """
    add aws vpn gateways as nodes and add associated metadata to associated networkx object

    NB: vpn gateway information is available only via a boto3.Client object


    Args:
        networks (dict): dict of network.Graph objects representing the topo of a given VPC and containing metadata
        vpc (boto3.Vpc): The VPC we're interested in
        session (boto3.Session): Session object initialized with API keys, region, etc.

    Returns: None

    """

    # setup some useful local variables
    network = networks[vpc.id]

    # must use ec2.client in order to access vpn gateway info
    ec2_client = session.client('ec2')

    filters = [{'Name': 'attachment.vpc-id', 'Values': [vpc.id]}]

    returned_data_dict = ec2_client.describe_vpn_gateways(Filters=filters)

    vpn_gws = returned_data_dict['VpnGateways']

    # the data we need is contained in a list, which is the value of an item in the dict returned above
    for vpn_gw in vpn_gws:
        # get vpn gw's attached to this VPC and add them as nodes
        # want the availability zone but it's not always available
        vpn_gw_name = get_aws_object_name(vpn_gw['Tags'])
        vpn_gw_id = vpn_gw['VpnGatewayId']
        vpngw_attributes = {'name': vpn_gw_name, 'state': vpn_gw['State'], 'avail_zone': vpn_gw.get('AvailabilityZone'),
                            'vpc_attachments': vpn_gw['VpcAttachments']}
        network.add_node(vpn_gw_id, **vpngw_attributes)
        logger.info('Added node {} to vpc: {}'.format(vpn_gw_id, vpc.id))


def get_nat_gateways(network, vpc, session):
    """
    add nat gateway nodes to network, along w/any pertinent meta data

    Using session b/c I can't find any reference to nat gateways at the Boto3.Resource level

    Args:
        network (networkx.Graph): Graph holding topo data for a given AWS VPC
        vpc (boto3.Vpc): the relevant VPC
        session (boto3.Session): session object initialized with api keys, region, etc.

    Returns: None

    """

    # create the client from session
    ec2_client = session.client('ec2')

    # get natgw iterable for this vpc  (list of dicts
    natgw_dict = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id, ]}])
    natgw_list = natgw_dict['NatGateways']  # list of dicts containing attributes of a given nat gateway

    # loop over and add as nodes, collecting desired metadata
    for gateway in natgw_list:
        natgw_name = gateway['NatGatewayId']
        attributes = {'state': gateway['State']}
        network.add_node(natgw_name, **attributes)
        logger.info('Added node {} to vpc: {}'.format(natgw_name, vpc.id))


def get_inetgw_data(networks, vpc):
    for gateway in vpc.internet_gateways.all():
        networks[vpc.id].add_node(gateway.id)
        logger.info('Added node {} to vpc: {}'.format(gateway.id, vpc.id))


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


def add_route_table_node(network, vpc, route_table):
    """
    add the route-table node type to the network graph

    Also extracts the AWS RouteTable name from the tags attribute and adds that data

    Args:
        vpc:
        network (networkx.Graph): graph representing the VPC topo and holding assocaited meta-data
        route_table (boto3.RouteTable): the route table to add to network graph

    Returns: None

    """

    # setup local variables
    route_table_name = get_aws_object_name(route_table.tags)

    # add "router" to the graph (AWS route table)
    network.add_node(route_table.id)
    network.node[route_table.id]['name'] = route_table_name
    logger.info('Added node {} to vpc: {}'.format(route_table.id, vpc.id))


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
    network_data_dict = network.graph
    route_table_data_dict = network.node[route_table.id]

    # add associated subnet list to the route table data, associated means *explicitly* configured via AWS API calls
    route_table_data_dict['assoc_subnets'] = []

    # add and init the flag indicating if this is the main route table for this vpc
    # starts False, changed to True when the main route table is found
    route_table_data_dict['main'] = False

    for assoc in route_table.associations_attribute:

        subnet_id = assoc.get('SubnetId')
        main_flag = assoc.get('Main')

        if not main_flag and subnet_id:  # this is an explicitly associated subnet

            route_table_data_dict['assoc_subnets'].append(subnet_id)

            # update the assoc_route_table key for the subnet
            # NB: all the subnets have to be added to the network before this happens
            logger.info('Adding route table: {} to assoc_route_table '
                        'field of subnet: {}'.format(route_table.id, subnet_id))

            network.node[subnet_id]['assoc_route_table'] = route_table.id

        elif main_flag and not subnet_id:  # this is the main rtb for this vpc
            route_table_data_dict['main'] = True

            # found 'the' main route table - check for possible error situations, such as two main route tables
            # if the id of the main route-table hasn't been set at the network (Graph) level yet, then set it
            if not network_data_dict['main_route_table']:
                network_data_dict['main_route_table'] = route_table.id
                logger.info('Updated main route table to {} for vpc {}'.format(route_table.id, vpc.id))

            # found another route table claiming to be main *with the same ID* as one found previously
            # I believe this should not occur so logging it if it does
            elif network_data_dict['main_route_table'] == route_table.id:  # found another, matching "main" rtb
                logger.info('Found main route table multiple times, which should probably not occur.  '
                            'vpc: {}, rtb: {}'.format(vpc.id, route_table.id))

            # another route table, with a different ID, is claiming to be main
            # this definitely shouldn't happen
            else:
                logger.info('Found two different main route tables: '
                            'vpc: {}, prev rtb-id: {}, '
                            'curr rtb-id: {}'.format(vpc.id, route_table.id,
                                                     network_data_dict['main_route_table']))

        # not main & no subnet OR main and subnet are nonsensical combo's alert (at least AFAIK)
        else:
            logger.info('Found possibly malformed subnet association data.  '
                        'vpc: {}, rtb: {}, main flag: {}, subnet-id: {}'.format(vpc.id, route_table.id, main_flag,
                                                                                subnet_id))


def get_route_table_routes(network, vpc, route_table):
    """
    extract route entries from a given route table and insert them into the network data model

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
        vpc:
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
        logger.info('Added route for {} to route-table {} '
                    'in vpc: {}'.format(dest_cidr or dest_pfx, route_table.id, vpc.id))


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

    # todo P1 *** look at "route propagation to get the vgw routes, + add'l vgw to topo that doesn't use propagation
    # todo (cont'd) in case that looks different - i.e. puts the routes in the route-table as usual

    for route_table in vpc.route_tables.all():
        add_route_table_node(network, vpc, route_table)

        # get the subnet associations data object from AWS API and iterate over it to extract useful info
        get_route_table_subnet_associations(network, vpc, route_table)

        # add the routes contained in this route table to our data model
        get_route_table_routes(network, vpc, route_table)


def get_elb_classics(network, vpc):
    """
    TBD

    Args:
        network:
        vpc:

    Returns:

    """
    logger.info('Coming Soon - ELB classic identification')


def get_elb_albs(network, vpc):
    """
    TBD

    Args:
        network:
        vpc:

    Returns:

    """
    logger.info('Coming Soon - ALB (ELBv2) identification')


def get_wafs(network, vpc):
    """
    TBD

    Args:
        network:
        vpc:

    Returns:

    """
    logger.info('Coming Soon - WAF identification')


def get_shield(network, vpc):
    """
    TBD

    Args:
        network:
        vpc:

    Returns:

    """
    logger.info('Coming Soon - AWS Sheild identification')


def add_explicit_subnet_edges(network, vpc):
    """
    add edges between route-tables and subnets that are explicitly associated

    NB: subnets in AWS that are not configured with an association are implicitly associated w/the main route table

    Args:
        vpc (boto3.Vpc): currently use vpc.id for logging purposes only
        network (networkx.Graph): Network representing the VPC containing the subnets to which edges will be added

    Returns: None

    """
    # add the explicitly associated subnets first, updating the assoc_route_table data item as you go
    node_dict = network.node  # local ref to dict of node data

    for cur_node in node_dict:
        if get_node_type(cur_node) == 'router':  # add edges from route-table (router) nodes
            route_table = cur_node
            subnets = node_dict[cur_node]['assoc_subnets']
            if len(subnets):  # verify there are subnets in the list
                for subnet in subnets:
                    network.add_edge(route_table, subnet)
                    logger.info('Added edge {} - {} in vpc {}'.format(route_table, subnet, vpc.id))


def add_implicit_subnet_edge(network, vpc):
    """
    add network edges for subnets not explicitly associated with a route table

    In AWS subnets not associated with a route-table are implicitly associated with the main route table for a given
    VPC.  This function adds edges for such subnets.

    Works by looping over the nodes in the network.  When a subnet is found, it cheks to see if that subnet's
    assoc_route_table field is 'None', indicating this subnet is implicitly associated with the VPC main route table.

    NB: the subnets, route-tables, and explicitly associated subnet edges must be added *before* this function
    is called.  This is b/c subnets are marked as implicitly associated with the VPC main route by virtue of
    the fact that get_router_data() didn't update the subnet's assoc_route_table field when it ran.


    Args:
        vpc (boto3.Vpc): currently use the vpc.id for logging purposes only
        network (networkx.Graph):  Graph holding network topo metadata for a given VPC

    Returns: None

    """

    # local ref to dict of node data
    node_dict = network.node
    main_route_table_id = network.graph['main_route_table']

    for cur_node in node_dict:

        if get_node_type(cur_node) == 'subnet':  # add edges from subnet nodes

            subnet_id = cur_node

            if not node_dict[subnet_id]['assoc_route_table']:
                network.add_edge(subnet_id, main_route_table_id)
                logger.info('Added edge {} - {} in vpc {}'.format(subnet_id, main_route_table_id, vpc.id))


def add_non_pcx_edges(network, vpc):
    """
    add connections for node types OTHER THAN vpc peering connections (pcx)

    Currently not sure this is covering all possible node types

    Also, seem to have lost notes indicating why pcx's can't be handled here.  recall it was to do w/having to visit
    all the VPC's first - in order to get all the pcx data so trying to add edges first caused dictionaries to be
    changed while they were being iterated over - which is bad

    Works by iterating over the nodes and checking their type.  When a route table (aka "router") is found, iterate
    over it's routes, grabbing the next hop information.  For NH's other than pcx's, add an edge for them

    Args:
        vpc (boto3.Vpc): currently used for logging purposes only
        network (networkx Graph): a Graph object from which to extract route data

    Returns: None

    """

    nodes = network.node

    for cur_node in nodes:
        if get_node_type(cur_node) == 'router':  # if it's a router

            router = cur_node

            route_list = nodes[router].get('routes')  # get the list of routes assoc w/this route-table

            if not route_list:
                logger.info('Skipping empty route table {}'.format(router))
                continue

            for route in route_list:

                nexthop_name = create_gateway_name(route)

                if nexthop_name.startswith('pcx'):
                    # eventually just skip pcx'es
                    logger.info(
                        'Got nexthop type pcx: {} in rtb: {}, not handled by this function(add_non_peer_conn_edges). '
                        'should be added later'.format(nexthop_name, router))

                # local is the route for the CIDR block attacked to the VPC itself, seems something like a hold down
                elif nexthop_name == 'local':
                    logger.info('Got nexthop node type/name "local" in route-table: {} - '
                                'currently this is uninteresting.  Logging occurrence for future inspection '
                                'if interest changes'.format(router))

                elif nexthop_name not in nodes:  # if the gw "name" is NOT in the node dict
                    # there's a problem, print an error and do nothing
                    logger.info('nexthop {} does not yet exist as a node in the network, '
                                'something has gone wrong'.format(nexthop_name))

                else:  # else add an edge
                    network.add_edge(router, nexthop_name)
                    logger.info('Added edge {} - {} in vpc {}'.format(router, nexthop_name, vpc.id))


def add_pcx_edges(network, vpc):
    """
    add connections for vpc peering connections (pcx)

    Works by iterating over the nodes and checking their type.  When a router (route-table) node is found, iterate
    over it's routes, grabbing the next hop information.  When the NH is a pcx, add the edge

    NB: this is currently handled separate from edges to other node types b/c there's an issue w/when the PCS's are
    added relative to adding edges to them - see add_non_pcx_edges()

    Args:
        vpc (boto3.Vpc): used for logging purposes
        network (networkx.Graph): Graph containing data about the network topo of a given VPC

    Returns: None

    """

    nodes = network.node

    for cur_node in nodes:

        if get_node_type(cur_node) == 'router':  # find the route-table nodes

            router = cur_node  # makes following code more readable

            route_list = nodes[router].get('routes')  # get the list of routes assoc w/this route-table

            if not route_list:
                logger.info('Skipping empty route table {}'.format(router))
                continue

            for route in route_list:

                nexthop_name = create_gateway_name(route)

                if nexthop_name.startswith('pcx'):
                    network.add_edge(router, nexthop_name)  # +edge: current rtb and the gw (next hop)
                    logger.info('Added edge {} - {} in vpc {}'.format(router, nexthop_name, vpc.id))


def build_nets(networks, vpcs, session=None):
    """
    Gather the network topology data used later for analysis and visualization

    This function drives the data collection by calling other functions that actually do the work

    One networkx.Graph object per aws VPC, each one contains topology/node data, e.g. subnets, route-tables
    (aka routers), vpc endpoints, etc.  Also associates relevant metadata with the nodes, which is used later
    by code that analyzes the topology and, optionally, renders it for visualization by humans.

    Args:
        networks (dict(networkx.Graph)):  each Graph holds the topo data for a given AWS VPC
        vpcs (boto3.Collection):  iterator of boto3.Vpc objects - from which most/all of the topo data comes
        session (boto3.Session): session object initialized with api keys and region information

    Returns: None

    """

    # todo verify correct handling of VPN gateways
    # todo P3 get NACL's

    for vpc in vpcs:
        # vpc object info @: https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#vpc
        vpc_attribs = {'cidr': vpc.cidr_block, 'isdefault': vpc.is_default,
                       'state': vpc.state, 'main_route_table': None}  # collect node attributes

        network = networks[vpc.id] = nx.Graph(vpc=vpc.id, **vpc_attribs)

        # need to pass networks dict to functions below because in at least one case (vpc peer connections) the network
        # to which a node must be added may not be the one used in this iteration of the for-loop
        # sec_groups = get_subnet_data(networks, vpc)
        get_subnets(networks, vpc)

        get_vpc_endpoint_data(network, vpc, session)

        get_customer_gw_data()  # should this be outside the VPC loop, e.g. are these logically outside the vpc?

        get_vpn_gw_data(networks, vpc, session)  # find the vpn gw's and add to networkx graph

        get_vpn_connection_data()  # are these outside the VPC?

        get_inetgw_data(networks, vpc)  # find internet gw's and add to network

        get_nat_gateways(network, vpc, session)

        # handle routers last as the function retrieving router data currently depends on the existence of all the other
        # node types
        get_router_data(network, vpc)

        get_peering_conn_data(network, vpc)

        get_elb_classics(network, vpc)  # doesn't do anything useful yet

        get_elb_albs(network, vpc)  # doesn't do anything useful yet

        get_wafs(network, vpc)  # doesn't do anything useful yet

        get_shield(network, vpc)  # doesn't do anything useful yet

        add_explicit_subnet_edges(network, vpc)

        add_implicit_subnet_edge(network, vpc)

        add_non_pcx_edges(network, vpc)

        add_pcx_edges(network, vpc)

        # todo P1 add handling of edges to: nat-inst, ???


def lookup_sec_group_data(group_id, sg_data):
    # in the sec group, for now, enhance to return sg ID and name (possibly tags)

    group_name = [sg.group_name for sg in sg_data if sg.id == group_id][0]

    return group_name


def fix_protocol_name(name):
    """
    return a human readable protocol name given one from AWS functions/methods

    AWS methods will typically return a readable name, except for when it should be 'ALL', in which case AWS API's will
    return '-1'.  This function simply checks to see if the protocol name is '-1' and returns the string 'ALL in that
    case, otherwise it returns the value provided in the parameter

    Args:
        name (string):  string representing the human readable protocol name or '-1', meaning ALL protocols

    Returns (string): protocol name, changing -1 to ALL

    """
    if name == '-1':
        return 'ALL'
    else:
        return name


def get_port_range(rule):
    """
    extract port range from a dict containing an "access control rule"

    Rule could be associated with either a security-group or with a network ACL

    Regarding rules from security-gorups vs NACL's and when the protocol is ICMP:

        Rules originating from security-groups store port ranges slightly differently than NACLS do.  In sec-groups,
        the ports are in the fields 'FromPort' & 'ToPort'.  NACL's store the from and to ports in a dict called
        'PortRange'.  Inside that dict are fields (keys) called 'To' and 'From'.

        Also, ICMP info is stored differently between NACL and security-group rules.  In both cases the ICMP is
        indicated by the appropriately named "protocol" field in the rule (i.e. it's named slightly differently between
        NACL's and security-group rules).  However, in security-group rules the type and code are stored in the
        'FromPort' and 'ToPort', respectively.  For NACL's the type and code are stored in a dict called 'IcmpTypeCode',
        similar to the way "regular" ports are stored.

        This function returns ICMP type and code data in the port range 2-tuple as (<type>, <code>) regardless.  To do
        so, it must make several checks to determine which type of rule it's been given

    Args:
        rule (dict): information related to a network access control rule, from sec-group rule or network acl

    Returns (tuple): two-tuple of the form (start, end) start/end are port numbers

    """

    port_range = ('NA', 'NA')

    if 'FromPort' in rule.keys():  # handles rules from sec-groups

        start = fix_protocol_name(rule['FromPort'])
        end = fix_protocol_name(rule['ToPort'])
        port_range = (start, end)

    elif 'PortRange' in rule.keys():  # handles rules from network ACL's

        start = fix_protocol_name(rule['PortRange']['From'])
        end = fix_protocol_name(rule['PortRange']['To'])
        port_range = (start, end)


    elif 'IcmpTypeCode' in rule.keys():  # handles case of ICMP for network acl
        type = rule['IcmpTypeCode']['Type']
        code = rule['IcmpTypeCode']['Code']
        port_range = (type, code)

    return port_range


def get_rule_add_range(rule):
    """
    gets the address range associated with a rule

    NB: the address range could be a source or dest range, but that is determined by calling functions

    Args:
        rule (???):

    Returns (list): list of address ranges

    """
    ranges = []  # gather srcs (curr aws allows only 1)

    for ip_range in rule['IpRanges']:  # ip ranges are list of dicts, which contain a single key 'cidrip'
        ranges.append(ip_range['CidrIp'])

    return ranges


def get_source_sec_groups(rule, security_groups):
    """
    get a list of the security groups in the source "field" of the rule

    Args:
        rule (boto3.EC2.SecurityGroup.ip_permissions/ip_permissions_egress): list(dicts) cont. sec-group access rules
        security_groups (dict): contains security-group data

    Returns (list): security-groups in the source of a rule

    """

    src_sec_groups = []  # gather (acct, sg_id) tuples, this is probably mutex with ip ranges

    if len(rule['UserIdGroupPairs']) > 0:

        for uid_group_pair in rule['UserIdGroupPairs']:
            group_id = uid_group_pair['GroupId']
            group_name = lookup_sec_group_data(group_id, security_groups)
            user_id = uid_group_pair['UserId']
            src_sec_groups.append((user_id, group_id, group_name))

    return src_sec_groups


# todo refactor to take only sec_group_ID and sec_group data dict - b/c the permissions are already in the latter
def get_access_rules(sec_group_id, permission_list, security_groups):  # helper func for build_subnet_rules
    """
     return data associated with access rules in an aws boto3.ec2.security_group.ip_pmissions (and egreess)

    NB: rule order does not matter in AWS SG ACL's b/c only permits are allowed

    Args:
        sec_group_id (string): aws security group ID
        permission_list (boto3.Ec2.SecurityGroup.ip_permissions): list(dicts) cont'g access rules
        security_groups (dict): contains security-group data

    Returns (list): rules in a flattened, more useful format

    """
    rules = []  # list of rules, rule is a dict with sec_grp_id, sources, proto and port info

    for rule in permission_list:

        # get the proto name
        proto_name = fix_protocol_name(rule['IpProtocol'])

        # get port range
        port_range = get_port_range(rule)

        if port_range == ('NA', 'NA') and proto_name == 'ALL':
            port_range == ('ALL', 'ALL')

        # get the sources, which may be cidr blocks or security groups
        src_sec_groups = get_source_sec_groups(rule, security_groups)

        add_ranges = get_rule_add_range(rule)
        add_ranges.extend(src_sec_groups)  # this should end up containing cidr ranges or group info, not both

        rules.append({'sgid': sec_group_id, 'src_dst': add_ranges, 'protocol': proto_name,
                      'ports': port_range})

    return rules


def build_sec_group_rule_dict(security_groups):
    """
    extract pertinent info from aws security group rules and store in a more useful form

    Args:
        security_groups (dict): contains security group data

    Returns (dict): security group rules

    """

    # place to put the rule data
    rules = {}

    for sg in security_groups:
        rules[sg.id] = {}

        # get rules in more concise form & assign to new fields in sg_rules
        rules[sg.id]['inacl'] = get_access_rules(sg.id, sg.ip_permissions, security_groups)

        rules[sg.id]['outacl'] = get_access_rules(sg.id, sg.ip_permissions_egress, security_groups)

    return rules


def get_sec_group_rules_by_subnet(networks, security_groups):
    """
    extract security group rules for a subnet from instance data and insert into the data model

    Finds the security groups associated with a given subnet and for each it extracts the associated
    rules.  Those rules are formatted and added to the networkx graph, for a given VPC, as an attribute of the
    associated subnet

    Args:
        networks (dict): network node data
        security_groups (boto3 collection(sec-groups): iterable that returns the security groups associated with a vpc

    Returns: None

    """
    # todo P3 determine if this can/should be refactored to use the collection of VPCs, similar to the nacl function
    # todo rename inacl to sg-inacl, similar for outacl, to distinguish from network acls

    sg_rules = build_sec_group_rule_dict(security_groups)  # build the dict of rules, to be indexed by sec_group ID

    # for each subnet node in a network, loop over the security groups of that subnet and pull the rules from the
    # rules dict created above
    for net, data in networks.iteritems():  # for each networkx graph object in dict called networks {net_name: netxobj}

        for n in data.node:  # loop over the graph's nodes

            if n.startswith('subnet'):  # only interested in subnet nodes
                subnet = data.node[n]
                subnet['inacl'] = []  # create empty lists in the network node dicts to accept acl info
                subnet['outacl'] = []

                for sg in subnet['sec_groups']:  # loop over set of sg's assoc. with this subnet
                    subnet['inacl'].extend(sg_rules[sg]['inacl'])  # add sg inacl to subnet inacl
                    subnet['outacl'].extend(sg_rules[sg]['outacl'])  # add sg inacl to subnet inacl


def get_nacls(networks, vpcs):
    """
    Get network ACL data and add to network topo data

    The NACLs are at the VPC level.  Each lists the subnets to which it applies.  This function will get the NACLs

    A later function will "copy" this data to the subnet leve of the data model so that it can be referenced from either
    direction (subnet > nacls or nacl > subnets

    Args:
        networks:
        vpcs (boto3.Collection.Vpc):  The VPC from which to get NACL data

    Returns: todo

    """
    # todo determine if rule extraction logic can be generalized and applied to both NACL's and SG rules

    for vpc in vpcs:

        graph_data = networks[vpc.id].graph
        graph_data['nacls'] = {}  # todo use setdefault?
        acl_data = graph_data['nacls']
        node_data = networks[vpc.id].node

        for acl in vpc.network_acls.all():

            acl_name = get_aws_object_name(acl.tags)
            acl_data[acl.id] = {'name': acl_name, 'default': acl.is_default, 'assoc_subnets': [],
                                'ingress_entries': [], 'egress_entries': []}

            logger.info('Begin adding NACL {} ({})'.format(acl.id, acl_name))

            for subnet_assoc in acl.associations:  # add assoc. subnets to list

                subnet = subnet_assoc['SubnetId']
                acl_data[acl.id]['assoc_subnets'].append(subnet)
                logger.info('Added {} to associated subnet list for NACL {}'.format(subnet, acl.id))

                node_data[subnet]['nacl'] = acl.id
                logger.info('Added NACL {} to subnet {}'.format(acl.id, subnet))

            # add entry/rule data
            for entry in acl.entries:
                ports = get_port_range(entry)
                proto_name = fix_protocol_name(entry['Protocol'])

                # using [entry[]] below to make value a list, which is consistent w/the type in the sec-group
                # originated rules.  also other functions expect this to be a list, not a string
                attribs = {'number': entry['RuleNumber'], 'action': entry['RuleAction'], 'protocol': proto_name,
                           'src_dst': [entry['CidrBlock']],
                           'ports': ports}

                if entry['Egress']:
                    acl_data[acl.id]['egress_entries'].append(attribs)
                    logger.info('Added entry to {} in network {}'.format(acl.id, vpc.id))
                else:
                    acl_data[acl.id]['ingress_entries'].append(attribs)
                    logger.info('Added entry to {} in network {}'.format(acl.id, vpc.id))


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
    logger.info('Render PyPlot {}'.format(output_dir))


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

    csvwriter.writerow('vpc_id subnet_id sec_group_id direction rule_num src_dst protocol port_range'.split())

    for net_id, net_data in networks.iteritems():

        for node_id, node_data in net_data.node.iteritems():

            if node_id.startswith('subnet'):  # set rules for subnets

                subnet = node_data  # use a different label for readability

                for acl in subnet['inacl']:  # inbound acl first
                    csvwriter.writerow([net_id, node_id, acl['sgid'], 'in', acl['src_dst'], acl['protocol'],
                                        acl['ports']])
                for acl in subnet['outacl']:  # inbound acl first
                    csvwriter.writerow([net_id, node_id, acl['sgid'], 'out', acl['src_dst'], acl['protocol'],
                                        acl['ports']])

    f.flush()
    f.close()


def render_nets(networks, graph_format=None, output_dir=None, yaml_export=False, csv_file=None):
    if graph_format:  # don't lower() if None (likely b/c format option not specified)
        graph_format = graph_format.lower()

    if not output_dir:  # use current directory if no output dir specified
        output_dir = os.path.curdir

    if not graph_format and yaml_export:  # no format specified, but yaml output requested (--export-to-yaml)
        logger.info('Render to YAML only')
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
            logger.info('Render to Gephi and YAML')
            for network in networks.values():
                render_gexf(network, output_dir)
                # add yaml export code
        else:
            logger.info('Render to Gephi only')
            for network in networks.values():
                render_gexf(network, output_dir)

    elif graph_format == 'pyplot':
        if yaml_export:
            logger.info('Render to PyPlot and YAML')
            for network in networks.values():
                render_pyplot(network, output_dir)
                # add yaml export code
        else:
            logger.info('Render to PyPlot only')
            for network in networks.values():
                render_pyplot(network, output_dir)

    elif graph_format is not None:
        logger.warning('Render - unknown format requested: {}'.format(graph_format))

    if csv_file:  # should be None if option not specified, otherwise it's a filename with opt. path

        # todo if keeping this feature, enhance it to handle "all" cases of path/filename that may be handed to it
        if os.path.split(csv_file)[0] == '':  # got file name only if path part is empty
            csv_file = os.path.join(output_dir, csv_file)  # save with other output files

        logger.info('Render export rules to CSV file {}'.format(csv_file))

        export_sgrules_to_csv(networks, outfile=csv_file)


def create_reverse_dict(dict):
    """
    adds the reverse-mapping to the mapping contained in the dict parameter

    assumes the dict is a 'single level' deep - i.e. all values are scalars

    Args:
        dict (dict): mapping to which the reverse mapping will be added

    Returns (dict): dict containing existing forward mappings and added reverse mappings

    """

    forward_length = len(dict)

    new = {}

    for k, v in dict.iteritems():
        new[v] = k

    if len(new) < forward_length:
        logger.info('Generated protocol name-to-number mapping from number-to-name, it contained multiple entries '
                    'with the same protocol name, which may result in errors when the reverse mapping is used')
    return new


def transform_risky_ports(risky_ports):
    """
    extract a list of ports per L4 protocol from the hierarchical dict of risky port info

    The risky ports data in the source YAML file is not in an easily searchable format.  This creates
    a new data structure populated from that source file that is easier to search.

    Args:
        risky_ports (dict): hierarchical dict mapping app names to ports and L4 protocols

    Returns (dict): dict whose keys are L4 protocol names each with an associated sets of ports

    """

    # todo P3 address ambiguity of mapping from port to risk (i.e. that's a 1:many relation)

    result = {'tcp': set(), 'udp': set()}

    for app, proto_port_data in risky_ports.items():
        for l4_proto, ports in proto_port_data.items():
            for port in ports:
                result[l4_proto].add(port)

    return result


def transform_allowed_icmp(allowed_icmp):
    """
    transform dict of permitted ICMP protocol "names" to a list of tuples of the form (<type>,<code>)

    See file data-model.txt for additional

    Args:
        allowed_icmp (dict): database of allowed ICMP types and codes, given by human readable names

    Returns (dict): lists of 2-tuples grouped by address family where each 2-tuple is as mentioned above

    """

    result = {'ipv4': [], 'ipv6': []}

    for af in ['ipv4', 'ipv6']:

        af_data = allowed_icmp.get(af)

        if af_data:

            for type_name, type_data in af_data.items():
                for type, codes in type_data.items():
                    for code in codes:
                        result[af].append((type, code))

    return result


def chk_ipv4_range_size(ace, threshold):
    """
    verify the src/dest ipv4 range is smaller than the threshold

    threshold is a MINIMUM prefix length

    NB: the src/dst is accessed via ace['src_dst'] and *it's a list*.  It may contain CIDR prefixes, security-group
    ID's and possibly other forms of src/dest information.

    Args:
        ace (dict): effectively an access control list entry - see the data-model.txt:network/node/subnet/(in|out)acl
        threshold (int): value of the threshold

    Returns (tuple): 2-tuple, (result, msg), result = pass|fail|other, msg=string message

    """
    # todo P1 fix this to handle non-CIDR block src-dest items, e.g. security-groups (# of hosts contained?)

    ranges = ace['src_dst']

    for range in ranges:

        if isinstance(range, tuple):  # todo P1 handle range containing PL, SG, etc.
            return 'other', 'Currently only support IPv4 CIDR ranges, got a range of type {}'.format(type(range))
        if range.startswith('sg'):  # not handling security groups yet
            return 'other', 'Got a security group {}'.format(range)  # todo P1 add handling for security groups
        elif not '/' in range:  # not handling anything that's not a CIDR block, i.e. has a /<pfx>
            return 'other', 'Got an unknown range type {}'.format(range)
        else:  # todo P1 determine if there are other cases to be handled here
            cidr = netaddr.IPNetwork(range)
            if cidr.prefixlen < threshold:
                return 'fail', range

    return 'pass', range


def chk_port_range_size(ace, threshold):
    """
    Verify port range size contained in an ace is not greater than threshold given

    port range size = end_port - start_port

    Args:
        ace (dict): an access control rule - contains address ranges, port ranges, protocols, etc.
        threshold (int): value to check against

    Returns (tuple): 2-tuple, (result, msg), result = pass|fail|other, msg=string message

    """

    if ace['protocol'].lower() == 'icmp':  # todo check for protocol number too?
        return 'other', 'Check port range does not apply to ICMP'

    elif ace['ports'] == ('NA', 'NA'):

        return 'other', 'Check port range size found an NA range {}'.format(ace['ports'])

    else:

        start = ace['ports'][0]
        end = ace['ports'][1]
        size = int(end) - int(start)

        if size > threshold:
            return 'fail', 'Port range size {} greater than threshold {}'.format(size, threshold)
        else:
            return 'pass', 'Port range size {} less than or equal to threshold {}'.format(size, threshold)


def chk_allowed_protocols(ace, allowed_protocols, num_to_name, name_to_num):
    """
    verify protocols in use in a network access rule are allowed

    Allowed protocols are defined in the file 'allowed_protocols.yaml'
    Args:
        num_to_name (dict): dict mapping L3 protocol numbers to names
        name_to_num (dict): dict mapping L3 protocol names to numbers
        allowed_protocols (list): list of allowed protocols (by number)
        ace (dict): an access control rule

    Returns:

    """

    # todo P3 make file to load configurable

    proto = ace['protocol']  # make more readable

    # we need both name and number here so get the one we don't yet know
    if proto.isdigit():  # protocol specified as a name/string
        proto_num = proto
        proto_name = num_to_name.get(proto_num)
    else:
        proto_name = proto
        proto_num = name_to_num.get(proto_name)

    if proto_num not in allowed_protocols:
        return 'fail', 'Protocol {} ({}) is not allowed'.format(proto_num, proto_name)

    else:
        return 'pass', 'Protocol {} ({}) is allowed'.format(proto_num, proto_name)


def chk_risky_ports(rule, risky_ports, allowed_icmp):
    """
    report if an access control rule contains ports deemed risky

    The risky_ports dict is of the form: {'tcp': set(<ports>), 'udp': set(<ports>)}

    Args:
        allowed_icmp (dict): icmp type/code pairs allowed, grouped by address family
        rule (dict): a network access control rule
        risky_ports (dict): a dict of risky ports grouped by L4 protocol

    Returns (tuple): 2 tuple of the form (result, msg), result = pass|fail|other; msg is a text message for humans

    """

    if rule['ports'] == ('NA', 'NA'):
        return 'other', 'Check risky ports - this rule appears to include all ports, so likely includes risky ports'

    rule_proto = rule['protocol']
    rule_start_port = rule['ports'][0]
    rule_end_port = rule['ports'][1]

    rule_ports = range(rule_start_port, rule_end_port + 1)  # need to add 1 b/c range() excludes the upper endpoint
    rule_ports = set(rule_ports)  # convert to set to enable set operations

    if rule_proto.isdigit():  # if not then protocol is already in string form
        i = int(rule_proto)
        if i == 6:
            rule_proto = 'tcp'
        if i == 17:
            rule_proto = 'udp'
        if i == 1:
            rule_proto = 'icmp'

    if rule_proto == 'icmp':
        for af in ['ipv4', 'ipv6']:
            if allowed_icmp[af]:  # check that the list of allowed type/codes is not empty
                if rule_ports.isdisjoint(allowed_icmp[af]):
                    return 'pass', 'Only allowed ICMP types/codes ' \
                                   'found in rule {type_code}'.format(type_code=rule['ports'])
                else:
                    return 'fail', 'Disallowed ICMP types/codes ' \
                                   'found in rule {type_code}'.format(type_code=rule['ports'])

    if rule_ports.isdisjoint(risky_ports[rule_proto]):
        return 'pass', 'No risky {} ports identified in rule port range {}'.format(rule_proto, rule['ports'])

    else:
        return 'fail', 'Risky {} ports identified in rule port range {}'.format(rule_proto, rule['ports'])


def check_security_group_rules(net_data, thresholds, allowed_protos, proto_num2name,
                               proto_name2num, risky_ports, allowed_icmp):
    """
    execute checks against rules originating from security groups

    Args:
        allowed_icmp (dict): permitted icmp types/codes, grouped by address family (ipv4, ipv6)
        net_data (dict): contains topo data, inc'g subnets, which contain the ACL info compiled from security groups
        thresholds (dict):  check threshold data
        allowed_protos (list): list of allowed protocols, by L3 protocol ID/number
        proto_num2name (dict): flat dict mapping L3 protocol numbers to protocol names
        proto_name2num (dict): flat dict mapping protocol names to L3 protocol numbers
        risky_ports (dict): dict listing risky ports by L4 protocols

    Returns (None):

    """

    # todo P3 update collection of SG originating rule data to store an "action" field to be consistent with NACLs

    for node, node_data in net_data.node.iteritems():

        if node.startswith('subnet'):
            subnet_id = node
            subnet_data = node_data

            if subnet_data['inacl']:  # todo P2 refactor this

                for entry in subnet_data['inacl']:  # todo P3 collapse these by parameterizing the result text?

                    entry_id = '/'.join([subnet_id, entry['sgid'], entry['protocol'], str(entry['ports'])])

                    results_list = []

                    result_ipv4_range_size = chk_ipv4_range_size(entry, thresholds['ip_v4_min_prefix_len'])
                    results_list.append(chk_port_range_size(entry, thresholds['port_range_max']))

                    results_list.append(
                        chk_allowed_protocols(entry, allowed_protos, proto_num2name, proto_name2num))

                    results_list.append(chk_risky_ports(entry, risky_ports, allowed_icmp))

                    # todo P1 handle logging for ipv4 range chk the same as the other checks!!!
                    # todo P2 determine if need to handle differently
                    # todo P2 figure out a better way to identify a rule than subnet-id/sg-id
                    if result_ipv4_range_size[0] == 'pass':

                        logger.info('Pass cider block size for rule {subnet_id}/{sg_id}: '
                                    '{result_msg}'.format(subnet_id=subnet_id, sg_id=entry['sgid'],
                                                          result_msg=result_ipv4_range_size[1]))

                    elif result_ipv4_range_size[0] == 'fail':
                        logger.info('Fail cider block size for rule {subnet_id}/{sg_id}: '
                                    '{result_msg}'.format(subnet_id=subnet_id, sg_id=entry['sgid'],
                                                          result_msg=result_ipv4_range_size[1]))

                    elif result_ipv4_range_size[0] == 'other':
                        logger.info('Security-group rule {subnet_id}/{sg_id} cidr block size check found something it '
                                    'could not parse {result_msg}'.format(subnet_id=subnet_id, sg_id=entry['sgid'],
                                                                          result_msg=result_ipv4_range_size[1]))

                    for result in results_list:
                        logger.info('{result} for rule {entry_id} {msg}'.format(
                            result=result[0].title(), entry_id=entry_id, msg=result[1]))


def check_network_acl_rules(nacl_data, thresholds, allowed_protos, proto_num2name, proto_name2num, risky_ports,
                            allowed_icmp):
    """
    execute checks against rules originating from security groups

    NB: this check ignores rules with the deny action

    Args:
        allowed_icmp:
        nacl_data (dict): contains network acl data for some vpc, see data-model.txt
        thresholds (dict):  check threshold data
        allowed_protos (list): list of allowed protocols, by L3 protocol ID/number
        proto_num2name (dict): flat dict mapping L3 protocol numbers to protocol names
        proto_name2num (dict): flat dict mapping protocol names to L3 protocol numbers
        risky_ports (dict): dict listing risky ports by L4 protocols

    Returns (None):

    """

    for nacl_id, nacl in nacl_data.iteritems():  # todo P3 collapse these by parameterizing the result text?


        for dir in ['ingress_entries', 'egress_entries']:

            for entry in nacl[dir]:

                # skip deny rules, though interesting in general, they do not enable potentially undesired comm's
                if entry['action'] == 'deny':
                    continue

                dir_string = dir.split('_', 1)[0]

                # entry_id is an attempt to identify an acl entry for later reference, it's not ideal
                entry_id = '/'.join(['{nacl_id}({nacl_name})'.format(nacl_id=nacl_id, nacl_name=nacl['name']),
                                     dir_string, str(entry['number']), entry['protocol'], str(entry['ports'])])

                results_list = []  # todo P3 move outside the "dir loop" to collect all results, then emit log msgs?

                result_ipv4_range_size = chk_ipv4_range_size(entry, thresholds['ip_v4_min_prefix_len'])
                results_list.append(chk_port_range_size(entry, thresholds['port_range_max']))

                results_list.append(
                    chk_allowed_protocols(entry, allowed_protos, proto_num2name, proto_name2num))

                results_list.append(chk_risky_ports(entry, risky_ports, allowed_icmp))

                # todo P1 handle logging for ipv4 range chk the same as the other checks!!!
                # todo P2 determine if need to handle differently
                # todo P2 figure out a better way to identify a rule than subnet-id/sg-id
                if result_ipv4_range_size[0] == 'pass':
                    logger.info('Pass cidr block size for rule {entry_id}: '
                                '{result_msg}'.format(entry_id=entry_id,
                                                      result_msg=result_ipv4_range_size[1]))

                elif result_ipv4_range_size[0] == 'fail':
                    logger.info('Fail cidr block size for rule {entry_id}: '
                                '{result_msg}'.format(entry_id=entry_id,
                                                      result_msg=result_ipv4_range_size[1]))

                elif result_ipv4_range_size[0] == 'other':
                    logger.info('NACL rule {entry_id} cidr block size check found something it '
                                'could not parse {result_msg}'.format(entry_id=entry_id,
                                                                      result_msg=result_ipv4_range_size[1]))

                # todo P3 if all results gathered before logging then this loop must move outside the "dir loop"
                for result in results_list:
                    logger.info('{result} for rule {entry_id} {msg}'.format(
                        result=result[0].title(), entry_id=entry_id, msg=result[1]))


def execute_rule_checks(networks):  # figure out what params to pass
    """
    function to drive rule checks

    Checks are made for rules containing:

        * address range size beyond a threshold (checks prefix length)
        * large port ranges, given by a threshold
        * prohibited L3 protocols
        * 'risky' ports (risky ports are locally definable via a file) <<< working on this one now

    NB: function relies on loading data into a dict for each of several yaml files.  Currently those files are
    hardcoded here and must reside in the same directory as the script

    The file 'proto-num2name.yaml' maps L3 protocol numbers to names only, a utility function
    is called here to add the reverse mapping

    Args:
        networks (dict): of networkx.Graph objects containing network topology data

    Returns:

    """
    # todo P1 support prefix lists and security groups as sources
    # todo P2 currently seg-group and nacl rule checks are separate - unify - likely means refactoring dict key names
    # todo P3 make yaml file loading configurable (e.g. file name/path, etc.)
    # todo P3 names of L3 protocols need to be "standardized"

    risky_apps = load_yaml_file('risky_apps2ports.yaml')
    thresholds = load_yaml_file('thresholds.yaml')
    proto_num_to_name = load_yaml_file('proto-num2name.yaml')
    allowed_proto_list = load_yaml_file('allowed_protocols.yaml')
    allowed_icmp = load_yaml_file('icmp_allowed.yaml')

    logger.info('Loaded check yaml files')

    proto_name_to_num = create_reverse_dict(proto_num_to_name)
    risky_ports = transform_risky_ports(risky_apps)
    allowed_icmp = transform_allowed_icmp(allowed_icmp)

    # loop over the networks, then the nodes, looking for subnets - which is where the aggregated SG rules are
    # then loop over the rules conducting checks
    for net, net_data in networks.iteritems():

        logger.info('Begin security-group rule checks')
        check_security_group_rules(net_data, thresholds, allowed_proto_list, proto_num_to_name, proto_name_to_num,
                                   risky_ports, allowed_icmp)

        logger.info('Begin NACL rule checks')
        check_network_acl_rules(net_data.graph['nacls'], thresholds, allowed_proto_list, proto_num_to_name,
                                proto_name_to_num, risky_ports, allowed_icmp)
