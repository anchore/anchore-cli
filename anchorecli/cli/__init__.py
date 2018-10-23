import os
import click
import subprocess
import sys
import logging

from . import image, policy, evaluate, subscription, registry, system, utils, repo, event, query, account

from anchorecli import version
import anchorecli.clients

#from anchoreservice.subsys import logger

@click.group()
@click.option('--debug', is_flag=True, help='Debug output to stderr')
@click.option('--u', help='Username (or use environment variable ANCHORE_CLI_USER)')
@click.option('--p', help='Password (or use environment variable ANCHORE_CLI_PASS)')
@click.option('--url', help='Service URL (or use environment variable ANCHORE_CLI_URL)')
@click.option('--api-version', help='Explicitly specify the API version to skip checking. Useful when swagger endpoint is inaccessible')
@click.option('--insecure', is_flag=True, help='Skip SSL cert checks (or use environment variable ANCHORE_CLI_SSL_VERIFY=<y/n>)')
@click.option('--json', is_flag=True, help='Output raw API JSON')

@click.version_option(version=version.version)
@click.pass_context
#@extended_help_option(extended_help="extended help")
def main_entry(ctx, debug, u, p, url, api_version, insecure, json):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    cli_opts = {
        'u': u,
        'p': p,
        'url': url,
        'api-version': api_version,
        'insecure': insecure,
        'json': json,
        'debug': debug
    }

    config = utils.setup_config(cli_opts)
    if config['debug']:
        logging.basicConfig(level=logging.DEBUG)
        
    ctx.obj = config

main_entry.add_command(image.image)
main_entry.add_command(evaluate.evaluate)
main_entry.add_command(policy.policy)
main_entry.add_command(subscription.subscription)
main_entry.add_command(registry.registry)
main_entry.add_command(repo.repo)
main_entry.add_command(system.system)
main_entry.add_command(event.event)
main_entry.add_command(query.query)
main_entry.add_command(account.account)
#main_entry.add_command(interactive.interactive)
