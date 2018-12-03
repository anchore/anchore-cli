import sys
import os
import re
import json
import time
import click
import logging

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}
_logger = logging.getLogger(__name__)

@click.group(name='system', short_help='System operations')
@click.pass_context
@click.pass_obj
def system(ctx_config, ctx):
    global config
    config = ctx_config

    if ctx.invoked_subcommand not in ['wait']:
        try:
            anchorecli.cli.utils.check_access(config)
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, 'system', {}, err))
            sys.exit(2)

@system.command(name='status', short_help="Check current anchore-engine system status")
def status():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.system_status(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'system_status', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'system_status', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@system.command(name='wait', short_help="Blocking operation that will return when anchore-engine is available and ready.")
@click.option('--timeout', type=float, default=-1.0, help="Time to wait, in seconds. If < 0, wait forever (default=-1)")
@click.option('--interval', type=float, default=5.0, help="Interval between checks, in seconds (default=5)")
@click.option("--feedsready", default='vulnerabilities', help='In addition to API and set of core services being available, wait until at least one full feed sync has been completed for the CSV list of feeds (default="vulnerabilities").')
@click.option("--servicesready", default='catalog,apiext,policy_engine,simplequeue,analyzer', help='Wait for the specified CSV list of anchore-engine services to have at least one service reporting as available (default="catalog,apiext,policy_engine,simplequeue,analyzer")')
def wait(timeout, interval, feedsready, servicesready):
    global config
    ecode = 0
    """
    Wait for an image to go to analyzed or analysis_failed status with a specific timeout

    :param timeout: 
    :param interval: 
    :param feedsready:
    :return:
    """
    try:
        sys.stderr.write("Starting checks to wait for anchore-engine to be available timeout={} interval={}\n".format(timeout, interval))
        ts = time.time()
        while timeout < 0 or time.time() - ts < timeout:
            sys.stderr.write("API availability: Checking anchore-engine URL ({})...\n".format(config['url']))
            _logger.debug("Checking API availability for anchore-engine URL ({})".format(config['url']))
            try:
                anchorecli.cli.utils.check_access(config)
                _logger.debug("check access success")
                break;
            except Exception as err:
                _logger.debug("check access failed, trying again")
            time.sleep(interval)
        else:
            raise Exception("timed out after {} seconds.".format(timeout))

        sys.stderr.write("API availability: Success.\n")

        while timeout < 0 or time.time() - ts < timeout:
            all_up = {}
            try:
                services_to_check = [x for x in servicesready.split(',') if x]
                for f in services_to_check:
                    all_up[f] = False
            except:
                all_up = {}

            sys.stderr.write("Service availability: Checking for service set ({})...\n".format(','.join(all_up.keys())))
            _logger.debug("Checking service set availability for anchore-engine URL ({})".format(config['url']))
            try:
                ret = anchorecli.clients.apiexternal.system_status(config)
                ecode = anchorecli.cli.utils.get_ecode(ret)
                if ret['success']:

                    for service_record in ret.get('payload', {}).get('service_states', []):
                        s = service_record.get('servicename', None)
                        if s:
                            if s not in all_up:
                                all_up[s] = False
                            try:
                                s_up = service_record.get('service_detail', {}).get('up', False)
                            except:
                                s_up = False
                            if s_up:
                                all_up[s] = s_up

                    if False not in all_up.values():
                        _logger.debug("full set of available engine services detected")
                        break;
                    else:
                        _logger.debug("service set not yet available {}".format(all_up))
                elif ret.get('httpcode', 500) in [401]:
                    raise Exception("service responded with 401 Unauthorized - please check anchore-engine credentials and try again")
            except Exception as err:
                print ("service status failed {}".format(err))
            time.sleep(interval)
        else:
            raise Exception("timed out after {} seconds.".format(timeout))
        sys.stderr.write("Service availability: Success.\n")


        if feedsready:
            all_up = {}
            try:
                feeds_to_check = feedsready.split(',')
                for f in feeds_to_check:
                    all_up[f] = False
            except:
                all_up = {}

            while timeout < 0 or time.time() - ts < timeout:
                sys.stderr.write("Feed sync: Checking sync completion for feed set ({})...\n".format(','.join(all_up.keys())))
                _logger.debug("Checking feed sync status for anchore-engine URL ({})".format(config['url']))
                try:
                    ret = anchorecli.clients.apiexternal.system_feeds_list(config)
                    if ret['success']:
                        for feed_record in ret.get('payload', []):
                            _logger.debug("response show feed name={} was last_full_sync={}".format(feed_record.get('name'), feed_record.get('last_full_sync')))
                            if feed_record.get('name', None) in all_up:
                                if feed_record.get('last_full_sync', None):
                                    all_up[feed_record.get('name')] = True

                        if False not in all_up.values():
                            _logger.debug("all requests feeds have been synced")
                            break
                        else:
                            _logger.debug("some feeds not yet synced {}".format(all_up))
                except Exception as err:
                    print ("service feeds list failed {}".format(err))
                time.sleep(interval)
            else:
                raise Exception("timed out after {} seconds.".format(timeout))

            sys.stderr.write("Feed sync: Success.\n")
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'system_wait', {}, err))
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
            print(anchorecli.cli.utils.format_output(config, 'delete_system_service', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'delete_system_service', {}, err))
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
            print(anchorecli.cli.utils.format_output(config, 'system_feeds_list', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'system_feeds_list', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@feeds.command(name="sync", short_help="Fetch latest updates from the feed service")
@click.option("--flush", is_flag=True, help="Flush all previous data, including CVE matches, and resync from scratch")
def feedsync(flush):
    global input
    ecode = 0

    try:
        answer = "n"
        try:
            print("\nWARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.\n")
            try:
                input = raw_input
            except NameError:
                pass
            answer = input("Really perform a manual feed data sync/flush? (y/N)")
        except Exception as err:
            answer = "n"

        if 'y' == answer.lower():
            ret = anchorecli.clients.apiexternal.system_feeds_sync(config, flush)
            ecode = anchorecli.cli.utils.get_ecode(ret)

            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'system_feeds_flush', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'system_feeds_flush', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
