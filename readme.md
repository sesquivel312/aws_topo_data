## Overview
Using python SDK (boto3) to gather topology and access control info.
Said info is stored in a networkx graph, one graph per VPC.

Access control information is gathered by subnet - by collecting the
union of all security groups applied to all instances in a given subnet.
Access rules are extracted from the groups.

Networkx is used to store data, export topo graph and/or to plot the
topo using pyplot.  NB: a local installation of graphviz is required to
handle the graphviz layout function.

```terraform/``` holds hashicorp terraform files for creating a test environment against which this script can be run.

* requires terrafrom to be installed
* must have valid AWS API creds (keys)
* use ```terraform apply``` and ```terraform destroy``` to create and destroy the AWS instances and other, associated resources