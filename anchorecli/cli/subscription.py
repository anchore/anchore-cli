import sys
import os
import re
import json
import click

import anchorecli.clients.apiexternal

config = {}

@click.group(name='subscription', short_help='Subscription operations')
@click.pass_obj
def subscription(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'subscription', {}, err))
        sys.exit(2)

@subscription.command(name='activate', short_help="Activate a subscription")
@click.argument('subscription_type', nargs=1)
@click.argument('subscription_key', nargs=1, required=False)
def activate(subscription_type, subscription_key):
    """
    SUBSCRIPTION_TYPE: Type of subscription. Valid options: 

      - tag_update: Receive notification when new image is pushed

      - policy_eval: Receive notification when image policy status changes

      - vuln_update: Receive notification when vulnerabilities are added, removed or modified

    SUBSCRIPTION_KEY: Fully qualified name of tag to subscribe to. Eg. docker.io/library/alpine:latest
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.activate_subscription(config, subscription_type, subscription_key)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'subscription_activate', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'subscription_activate', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@subscription.command(name='deactivate', short_help="Deactivate a subscription")
@click.argument('subscription_type', nargs=1)
@click.argument('subscription_key', nargs=1, required=False)
def deactivate(subscription_type, subscription_key):
    """
    SUBSCRIPTION_TYPE: Type of subscription. Valid options: 

      - tag_update: Receive notification when new image is pushed

      - policy_eval: Receive notification when image policy status changes

      - vuln_update: Receive notification when vulnerabilities are added, removed or modified

    SUBSCRIPTION_KEY: Fully qualified name of tag to subscribe to. Eg. docker.io/library/alpine:latest
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.deactivate_subscription(config, subscription_type, subscription_key)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'subscription_deactivate', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'subscription_deactivate', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@subscription.command(name='list', short_help="List all current subscriptions")
def subscriptionlist():
    ecode = 0
    try:
        ret = anchorecli.clients.apiexternal.get_subscription(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'subscription_list', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'subscription_list', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

