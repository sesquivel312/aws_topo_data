variable "access_key" {}
variable "secret_key" {}

provider "aws" {
	access_key	= "${var.access_key}"
	secret_key	= "${var.secret_key}"
	region 		= "us-west-2"
}

resource "aws_eip" "pub_a1" {
	network_interface = "${aws_instance.host-a.network_interface_id}"
}

resource "aws_eip" "pub_a2" {  # attach to host-a, nic 1 (2nd)
	network_interface = "${aws_network_interface.en1.id}"
}

resource "aws_eip" "pub_b1" {
	instance = "${aws_instance.host-b.id}"
}

resource "aws_subnet" "a2" {
	vpc_id = "${vpc-39abbb5b}"
	cidr_block = "${172.31.48.20/20}"
}

resource "aws_subnet" "a3" {
	vpc_id = "${vpc-39abbb5b}"
	cidr_block = "${172.31.32.20/20}"
}
resource "aws_eip" "eip_nat_a1" { # don't think I need any args for this
}

resource "aws_nat_gateway" "ngw_a1" {
	allocation_id = "${aws_eip.eip_nat_a1.id}"
	subnet_id = "${aws_subnet.a2.id}"
	depends_on = ["aws_internet_gateway.igw-a1"] # assuming I can use the existing igw
}

resource "aws_network_interface" "en1" {
	subnet_id = "subnet-92f3ade4" # subnet-a-1
	security_groups = ["sg-a97be5d0"] # sg-a-other-2
	attachment {
		instance = "${aws_instance.host-a.id}"
		device_index = 1
	}
}

resource "aws_route" "nat" {
	route_table_id = "rtb-7a786b18"
	destination_cidr_block = "0.0.0.0/0"
	depends_on = ["aws_route_table."] << probably need to build this
	nat_gateway_id = "${aws_nat_gateway.ngw_a1.id}"
}

resource "aws_instance" "host-a" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "subnet-92f3ade4"  # subnet-a-1
	vpc_security_group_ids = ["sg-48318f31","sg-ec7be595"]  # sg-a-base, sg-a-other-1
}

resource "aws_instance" "host-a2" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "${aws_subnet.a3.id}"  # subnet-a-3
	vpc_security_group_ids = ["sg-48318f31","sg-ec7be595"]  # sg-a-base, sg-a-other-1
}

resource "aws_instance" "host-b" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "subnet-8de5e3e9"  # subnet-b-1
	vpc_security_group_ids = ["sg-1d318f64"]  # sg-b-base 
}

