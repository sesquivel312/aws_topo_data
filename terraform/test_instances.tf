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

resource "aws_network_interface" "en1" {
	subnet_id = "subnet-92f3ade4" # subnet-a-1
	security_groups = ["sg-a97be5d0"] # sg-a-other-2
	attachment {
		instance = "${aws_instance.host-a.id}"
		device_index = 1
	}
}

resource "aws_instance" "host-a" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "subnet-92f3ade4"  # subnet-a-1
	vpc_security_group_ids = ["sg-48318f31","sg-ec7be595"]  # sg-a-base, sg-a-other-1
}

resource "aws_instance" "host-b" {
	ami				= "ami-8a72cdea"
	instance_type	= "t1.micro"
	subnet_id		= "subnet-8de5e3e9"  # subnet-b-1
	vpc_security_group_ids = ["sg-1d318f64"]  # sg-b-base 
}

