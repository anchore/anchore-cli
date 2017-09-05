import sys
import os
import re
import json
import click

import anchorecli.clients.apiexternal

config = {}

@click.group(name='registry', short_help='Registry operations')
@click.pass_obj
def registry(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'registry', {}, err)
        sys.exit(2)

@registry.command(name='add', short_help="Add a registry")
@click.argument('registry', nargs=1, required=True)
@click.argument('registry_user', nargs=1, required=True)
@click.argument('registry_pass', nargs=1, required=True)
@click.option('--insecure', is_flag=True, default=False, help="Allow connection to registry without SSL cert checks (ex: if registry uses a self-signed SSL certificate)")
def add(registry, registry_user, registry_pass, insecure):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000

    REGISTRY_USER: Username

    REGISTRY_PASS: Password
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.add_registry(config, registry=registry, registry_user=registry_user, registry_pass=registry_pass, insecure=insecure)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'registry_add', {}, ret['payload'])
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'registry_add', {}, err)
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)

@registry.command(name='update', short_help="Update an existing registry")
@click.argument('registry', nargs=1, required=True)
@click.argument('registry_user', nargs=1, required=True)
@click.argument('registry_pass', nargs=1, required=True)
@click.option('--insecure', is_flag=True, default=False, help="Allow connection to registry without SSL cert checks (ex: if registry uses a self-signed SSL certificate)")
def upd(registry, registry_user, registry_pass, insecure):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000

    REGISTRY_USER: Username

    REGISTRY_PASS: Password
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.update_registry(config, registry=registry, registry_user=registry_user, registry_pass=registry_pass, insecure=insecure)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'registry_update', {}, ret['payload'])
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'registry_update', {}, err)
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)

@registry.command(name='del', short_help="Delete a registry")
@click.argument('registry', nargs=1, required=True)
def delete(registry):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.delete_registry(config, registry)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'registry_delete', {}, ret['payload'])
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'registry_delete', {}, err)
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)

@registry.command(name='list', short_help="List all current registries")
def registrylist():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_registry(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'registry_list', {}, ret['payload'])
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'registry_list', {}, err)
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)

@registry.command(name='get', short_help="Get a registry")
@click.argument('registry', nargs=1, required=True)
def get(registry):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_registry(config, registry=registry)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'registry_get', {}, ret['payload'])
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'registry_get', {}, err)
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)

