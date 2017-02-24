# define variable for vpcid lookups
variable "vpcid" {  # access with: var.vpcid["vpc-a"]
	default = {
		vpc-a = "vpc-39abbb5b"
		vpc-b = "vpc-79dbc21d"
	}
}

# define vars for security group lookups
variable "secgrpid" {
	default = {
		sg-a0 = "sg-48318f31"
		sg-a1 = "sg-ec7be595"
		sg-a2 = "sg-a97be5d0"
		sg-b0 = "sg-1d318f64"
		sg-b1 = "sg-4e78e637"
		sg-b2 = "sg-cc78e6b5"
	}
}

# define vars for keys
variable "access_key" {}
variable "secret_key" {}

# define provider info
provider "aws" {
	access_key	= "${var.access_key}"
	secret_key	= "${var.secret_key}"
	region 		= "us-west-2"
}

# def subnets
## sn-a1 << dual homed host
resource "aws_subnet" "sn-a1" {
	vpc_id = "${var.vpcid["vpc-a"]}"
	cidr_block = "172.31.64.0/20"
}

## sn-a2 << nat gw here
resource "aws_subnet" "sn-a2" {
	vpc_id = "${var.vpcid["vpc-a"]}"
	cidr_block = "172.31.48.0/20"
}

## sn-a3 (private)
resource "aws_subnet" "sn-a3" {
	vpc_id = "${var.vpcid["vpc-a"]}"
	cidr_block = "172.31.32.0/20"
}

## sn-a4 (private, no association)
resource "aws_subnet" "sn-a4" {
	vpc_id = "${var.vpcid["vpc-a"]}"
	cidr_block = "172.31.0.0/20"
}

## sn-b1
resource "aws_subnet" "sn-b1" {
	vpc_id = "${var.vpcid["vpc-b"]}"
	cidr_block = "172.16.0.0/20"
}

## sn-b2 not assocaited w/rtb
resource "aws_subnet" "sn-b2" {
	vpc_id = "${var.vpcid["vpc-b"]}"
	cidr_block = "172.16.16.0/20"
}

# define routers
## rt rt-a1
resource "aws_route_table" "rt-a1" {
	vpc_id = "${var.vpcid["vpc-a"]}"
}

## rt-a2, no explictly attached subnets
resource "aws_route_table" "rt-a2" {
	vpc_id = "${var.vpcid["vpc-a"]}"
}

## rt-b1
resource "aws_route_table" "rt-b1" {
	vpc_id = "${var.vpcid["vpc-b"]}"
}

# def pcxs
## a-b
resource "aws_vpc_peering_connection" "pcx-a-b" {
	vpc_id = "${var.vpcid["vpc-a"]}"
	peer_vpc_id = "${var.vpcid["vpc-b"]}"
}

# def igw's
## ig-a1
resource "aws_internet_gateway" "ig-a1" {
	vpc_id = "${var.vpcid["vpc-a"]}"
}

## ig-b1
resource "aws_internet_gateway" "ig-b1" {
	vpc_id = "${var.vpcid["vpc-b"]}"
}


# def nat gateways
## eip for ngw
resource "aws_eip" "eip-nat1" { # don't think I need any args for this
}

## ngw-a2-1
resource "aws_nat_gateway" "ngw-a1" {
	allocation_id = "${aws_eip.eip-nat1.id}"
	subnet_id = "${aws_subnet.sn-a2.id}"
	# depends_on = ["${aws_internet_gateway.ig-a1.id}"]
}

# def nics
## n-a1 << to be attached to host h-a1
resource "aws_network_interface" "ni-a1" {
	subnet_id = "${aws_subnet.sn-a1.id}"
	security_groups = ["${var.secgrpid["sg-a0"]}", "${var.secgrpid["sg-a2"]}"]
	attachment = {
		instance = "${aws_instance.h-a1.id}"
		device_index = 1
	}
}

# def instances
## h-a1 > sn: pub-a-1
resource "aws_instance" "h-a1" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "${aws_subnet.sn-a1.id}"
	vpc_security_group_ids = ["${var.secgrpid["sg-a0"]}", "${var.secgrpid["sg-a1"]}"]
}

## h-a2
resource "aws_instance" "h-a2" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "${aws_subnet.sn-a3.id}"
	vpc_security_group_ids = ["${var.secgrpid["sg-a1"]}", "${var.secgrpid["sg-a2"]}"]
}

## h-b1
resource "aws_instance" "h-b1" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "${aws_subnet.sn-b1.id}"
	vpc_security_group_ids = ["${var.secgrpid["sg-b0"]}", "${var.secgrpid["sg-b2"]}"]
}

# def routes
## @rt-a1 0/0 > ig-a1
resource "aws_route" "rt-a1-def" {
	route_table_id = "${aws_route_table.rt-a1.id}"
	destination_cidr_block = "0.0.0.0/0"
	# depends_on = ["${aws_route_table.rt-a1.id}"]
	gateway_id = "${aws_internet_gateway.ig-a1.id}"
}

## @rt-a1 172.16/16 > pcx-a-b
resource "aws_route" "rt-a1-intervpc" {
	route_table_id = "${aws_route_table.rt-a1.id}"
	destination_cidr_block = "172.16.0.0/16"
	# depends_on = ["${aws_route_table.rt-a1.id}"]
	vpc_peering_connection_id = "${aws_vpc_peering_connection.pcx-a-b.id}"
}

## @rt-a2 0/0 > ngw-a1
resource "aws_route" "rt-a2-nat" {
	route_table_id = "${aws_route_table.rt-a2.id}"
	destination_cidr_block = "0.0.0.0/0"
	# depends_on = ["${aws_route_table.rt-a2.id}", "${aws_nat_gateway.ngw-a1.id}"]
	nat_gateway_id = "${aws_nat_gateway.ngw-a1.id}"
}

## @rt-b1 0/0 > ig-a2
resource "aws_route" "rt-b1-def" {
	route_table_id = "${aws_route_table.rt-b1.id}"
	destination_cidr_block = "0.0.0.0/0"
	# depends_on = ["${aws_route_table.rt-b1.id}"]
	gateway_id = "${aws_internet_gateway.ig-b1.id}"
}

## @rt-b1 172.31/16 > pcx-a-b
resource "aws_route" "rt-b1-intervpc" {
	route_table_id = "${aws_route_table.rt-b1.id}"
	destination_cidr_block = "172.31.0.0/16"
	# depends_on = ["${aws_route_table.rt-b1.id}"]
	vpc_peering_connection_id = "${aws_vpc_peering_connection.pcx-a-b.id}"
}

# def subnet route table associations
## @rta1 > sna1, named for associated subnet
resource "aws_route_table_association" "sna1" {  
	subnet_id = "${aws_subnet.sn-a1.id}"
	route_table_id = "${aws_route_table.rt-a1.id}"
}

## @rta1 > sna2
resource "aws_route_table_association" "sna2" {  
	subnet_id = "${aws_subnet.sn-a2.id}"
	route_table_id = "${aws_route_table.rt-a1.id}"
}

## @rta1 > sna3
resource "aws_route_table_association" "sna3" {  
	subnet_id = "${aws_subnet.sn-a3.id}"
	route_table_id = "${aws_route_table.rt-a2.id}"
}

## @rtb1 > snb1
resource "aws_route_table_association" "snb1" {  
	subnet_id = "${aws_subnet.sn-b1.id}"
	route_table_id = "${aws_route_table.rt-b1.id}"
}

# def eip's
## a1 >> associate to instance h-a1
resource "aws_eip" "eip-a1" {
	network_interface = "${aws_instance.h-a1.network_interface_id}"
}

## a2 >> assoc to nic n-a1 (ultimately h-a1 also)
resource "aws_eip" "eip-a2" {  # attach to h-a1, nic 1 (2nd)
	network_interface = "${aws_network_interface.ni-a1.id}"
}

## b1 >> instance h-b1
resource "aws_eip" "eip-b1" {
	instance = "${aws_instance.h-b1.id}"
}

