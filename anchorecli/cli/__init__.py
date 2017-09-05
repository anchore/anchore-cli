import os
import click
import subprocess
import sys
import logging

import image, policy, evaluate, subscription, registry, system
from anchorecli import version
import anchorecli.clients

#from anchoreservice.subsys import logger

@click.group()
@click.option('--debug', is_flag=True, help='Debug output to stderr')
@click.option('--u', help='Username (or use environment variable ANCHORE_CLI_USER)')
@click.option('--p', help='Password (or use environment variable ANCHORE_CLI_PASS)')
@click.option('--url', help='Service URL (or use environment variable ANCHORE_CLI_URL)')
@click.option('--insecure', is_flag=True, help='Skip SSL cert checks (or use environment variable ANCHORE_CLI_SSL_VERIFY=<y/n>)')
@click.option('--json', is_flag=True, help='Output raw API JSON')

@click.version_option(version=version.version)
@click.pass_context
#@extended_help_option(extended_help="extended help")
def main_entry(ctx, debug, u, p, url, insecure, json):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    if insecure:
        verify = 'n'
    else:
        verify = False
        
    if json:
        jsonmode = 'y'
    else:
        jsonmode = False

    #jsonmode = 'y'
    #if niceoutput:
    #    jsonmode = False

    config_defaults = {
        'ANCHORE_CLI_USER': None,
        'ANCHORE_CLI_PASS': None,
        'ANCHORE_CLI_URL': "http://localhost/v1/",
        'ANCHORE_CLI_SSL_VERIFY': "y",
        'ANCHORE_CLI_JSON': "n"
    }
    config_params = {
        'ANCHORE_CLI_USER': u,
        'ANCHORE_CLI_PASS': p,
        'ANCHORE_CLI_URL': url,
        'ANCHORE_CLI_SSL_VERIFY': verify,
        'ANCHORE_CLI_JSON': jsonmode
    }

    for e in config_params.keys():
        if not config_params[e]:
            try:
                config_params[e] = os.environ[e]
            except:
                config_params[e] = config_defaults[e]

    for boolkey in ['ANCHORE_CLI_SSL_VERIFY', 'ANCHORE_CLI_JSON']:
        if config_params[boolkey].lower() == 'y':
            config_params[boolkey] = True
        else:
            config_params[boolkey] = False
        
    config = {
        'user':config_params['ANCHORE_CLI_USER'],
        'pass':config_params['ANCHORE_CLI_PASS'],
        'url':config_params['ANCHORE_CLI_URL'],
        'ssl_verify':config_params['ANCHORE_CLI_SSL_VERIFY'],
        'jsonmode':config_params['ANCHORE_CLI_JSON'],
        'debug':debug

    }

    ctx.obj = config

main_entry.add_command(image.image)
main_entry.add_command(evaluate.evaluate)
main_entry.add_command(policy.policy)
main_entry.add_command(subscription.subscription)
main_entry.add_command(registry.registry)
main_entry.add_command(system.system)
#main_entry.add_command(interactive.interactive)
