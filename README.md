# Overview
The Anchore CLI provides a command line interface on top of the [Anchore Engine](https://github.com/anchore/anchore-engine) REST API.

Using the Anchore CLI users can manage and inspect images, policies, subscriptions and registries.

## Installation

### Installing Anchore CLI from source

The Anchore CLI can be installed from source using the Python pip utility

    git clone https://github.com/anchore/anchore-cli
    cd anchore-cli
    pip install --user --upgrade . 
    
Or can be installed from the installed form source from the Python [PyPI](https://pypi.python.org/pypi) package repository.


### Installing Anchore CLI on CentOS and Red Hat Enterprise Linux

    yum install -y epel-release
    yum install -y python-pip
    pip install anchore-cli

### Installing Anchore CLI on Debian and Ubuntu

    apt-get update 
    apt-get install python-pip
    pip install anchore-cli 


## Configuring the Anchore CLI

By default the Anchore CLI will try to connect to the Anchore Engine at http://localhost/v1 with no authentication.
The username, password and URL for the server can be passed to the Anchore CLI as command line arguments.

    --u   TEXT   Username     eg. admin
    --p   TEXT   Password     eg. foobar
    --url TEXT   Service URL  eg. http://localhost:8228/v1
   
Rather than passing these parameters for every call to the cli they can be stores as environment variables.

    ANCHORE_CLI_URL=http://myserver.example.com:8228/v1
    ANCHORE_CLI_USER=admin
    ANCHORE_CLI_PASS=foobar

