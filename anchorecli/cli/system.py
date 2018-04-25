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

@system.command(name='del', short_help="Delete a non-active service from anchore-engine")
@click.argument('host_id', nargs=1)
@click.argument('servicename', nargs=1)
def delete(host_id, servicename):
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.delete_system_service(config, host_id, servicename)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'delete_system_service', {}, ret['payload'])
        else:
            raise Exception(json.dumps(ret['error'], indent=4))
    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'delete_system_service', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@system.command(name='prune', short_help="Use to remove unused/old data")
@click.option("--filter-notdangling", is_flag=True, help="Include resources even if they are not orphaned")
@click.option("--filter-olderthan", default=None, help="Filter resources to those older than specified number of hours")
@click.option("--dontask", is_flag=True, help="Do not ask for confirmation")
def prune(filter_notdangling, filter_olderthan, dontask):
    ecode = 0

    dangling = not filter_notdangling
    if filter_olderthan:
        olderthan=float(filter_olderthan) * 60.0 * 60.0
    else:
        olderthan=None

    try:
        prune_candidates = None
        ret = anchorecli.clients.apiexternal.get_prune_candidates(config, 'all', dangling=dangling, olderthan=olderthan)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            prune_candidates = ret['payload']
            print anchorecli.cli.utils.format_output(config, 'prune_candidates', {}, ret['payload'])
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

        if prune_candidates and 'prune_candidates' in prune_candidates and prune_candidates['prune_candidates']:

            if dontask:
                answer = "y"
            else:
                try:
                    answer = raw_input("Really prune all above resources? (y/N)")
                except:
                    answer = "n"

            if 'y' == answer.lower():
                try:
                    ret = anchorecli.clients.apiexternal.perform_prune(config, 'all', prune_candidates)
                    ecode = anchorecli.cli.utils.get_ecode(ret)
                    if ret['success']:
                        print anchorecli.cli.utils.format_output(config, 'pruned_resources', {}, ret['payload'])
                    else:
                        raise Exception(json.dumps(ret['error'], indent=4))
                except Exception as err:
                    raise err
        

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'prune', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@system.group(name="feeds", short_help="Feed data operations")
def feeds():
    pass

@feeds.command(name="list", short_help="Get a list of loaded data feeds.")
def list():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.system_feeds_list(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'system_feeds_list', {}, ret['payload'])
        else:
            raise Exception(json.dumps(ret['error'], indent=4))
    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'system_feeds_list', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@feeds.command(name="sync", short_help="Fetch latest updates from the feed service")
@click.option("--flush", is_flag=True, help="Flush all previous data, including CVE matches, and resync from scratch")
def flush(flush):
    ecode = 0

    try:
        answer = "n"
        try:

            print "\nWARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.\n"
            answer = raw_input("Really perform a manual feed data sync/flush? (y/N)")
        except:
            answer = "n"

        if 'y' == answer.lower():
            ret = anchorecli.clients.apiexternal.system_feeds_sync(config, flush)
            ecode = anchorecli.cli.utils.get_ecode(ret)

            if ret['success']:
                print anchorecli.cli.utils.format_output(config, 'system_feeds_flush', {}, ret['payload'])
            else:
                raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'system_feeds_flush', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
