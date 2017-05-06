## Usage

```get_topo.py [options]```

**Useful Options**

*todo* add more usage detail here ...


## Overview
Using python SDK (boto3) to gather topology and access control info.
Said info is stored in a networkx graph, one graph per VPC.

    **NB:** Boto3 includes a customized Requests library (HTTP reqeusts). It
     Handles proxy via environment variables only and even then supports
     only basic auth against the proxy using the proxy URL itself.  This
     script effectively **does not** currently support accessing the AWS
     API via a proxy

The topo data can be used to render a visualization of the topology.

Currently supported formats include:
* *.png (via PyPlot)
* Gephi - (requries Gephi to view the exported data)
* *todo* add the rest ...


Access control information is gathered by subnet - by collecting the
union of all security groups applied to all instances in a given subnet.
Access rules are extracted from the groups.

Networkx is used to store data, export topo graph and/or to plot the
topo using pyplot.

    NB: a local installation of graphviz is required to
    handle the graphviz layout function.

```terraform/``` holds hashicorp terraform files for creating a test environment against which this script can be run.

* requires terrafrom to be installed
* must have valid AWS API creds (keys)
* use ```terraform apply``` and ```terraform destroy``` to create and destroy the AWS instances and other, associated resources



### Incomplete list of things this script does *NOT* do

* Parse vpce policies
* Deal with instances that carry transit traffic (e.g. IPS'es, etc.)
* Support IPv6

*todo* add info re: credentials (inc. environment variables)