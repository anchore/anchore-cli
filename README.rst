Overview
========

The Anchore CLI provides a command line interface on top of the `Anchore Engine <https://github.com/anchore/anchore-engine>`_ REST API.

Using the Anchore CLI users can manage and inspect images, policies, subscriptions and registries.

Installing Anchore CLI from source
==================================

The Anchore CLI can be installed from source using the Python pip utility

.. code::

    git clone https://github.com/anchore/anchore-cli
    cd anchore-cli
    pip install --user --upgrade . 

Or can be installed from the installed form source from the Python `PyPI <https://pypi.python.org/pypi>`_ package repository.

Installing Anchore CLI on CentOS and Red Hat Enterprise Linux
=============================================================

.. code::

    yum install -y epel-release
    yum install -y python-pip
    pip install anchorecli

Installing Anchore CLI on Debian and Ubuntu
===========================================

.. code::

    apt-get update 
    apt-get install python-pip
    pip install anchorecli 

Configuring the Anchore CLI
===========================

By default the Anchore CLI will try to connect to the Anchore Engine at ``http://localhost/v1`` with no authentication.
The username, password and URL for the server can be passed to the Anchore CLI as command line arguments.

.. code::

    --u   TEXT   Username     eg. admin
    --p   TEXT   Password     eg. foobar
    --url TEXT   Service URL  eg. http://localhost:8228/v1
 
Rather than passing these parameters for every call to the cli they can be stores as environment variables.

.. code::

    ANCHORE_CLI_URL=http://myserver.example.com:8228/v1
    ANCHORE_CLI_USER=admin
    ANCHORE_CLI_PASS=foobar

Command line examples
=====================

Add an image to the Anchore Engine

.. code::

    anchore-cli image add docker.io/library/debian:latest 
  
List images analyzed by the Anchore Engine

.. code::

    anchore-cli image list 
  
List operating system packges present in an image

.. code::

    anchore-cli image content docker.io/library/nginx:latest os 
  
Subscribe to receive webhook notifications when new CVEs are added to an update

.. code::

    anchore-cli subscription activate vuln_update docker.io/library/ubuntu:latest

More Information
================

For further details on use of the Anchore CLI with the Anchore Engine please refer to the `Anchore Engine Wiki <https://github.com/anchore/anchore-engine/wiki/>`_
