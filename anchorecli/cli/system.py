import sys
import os
import re
import json
import click
import urllib

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}

@click.group(name='system', short_help='System operations')
@click.pass_obj
def system(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'system', {}, err)
        sys.exit(2)

@system.command(name='status', short_help="Check current anchore-engine system status")
def status():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.system_status(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'system_status', {}, ret['payload'])
        else:
            raise Exception(json.dumps(ret['error'], indent=4))
    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'system_status', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
