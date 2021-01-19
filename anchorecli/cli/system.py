import sys
import json
import time
import click
import logging

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}
_logger = logging.getLogger(__name__)


class WaitOnDisabledFeedError(Exception):
    pass


@click.group(name="system", short_help="System operations")
@click.pass_context
@click.pass_obj
def system(ctx_config, ctx):
    global config
    config = ctx_config

    if ctx.invoked_subcommand not in ["wait"]:
        try:
            anchorecli.cli.utils.check_access(config)
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, "system", {}, err))
            sys.exit(2)


@system.command(name="status", short_help="Check current anchore-engine system status")
def status():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.system_status(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "system_status", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "system_status", {}, err)
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@system.command(
    name="errorcodes",
    short_help="Describe available anchore system error code names and descriptions",
)
def describe_errorcodes():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.describe_error_codes(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "system_describe_error_codes", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "system_describe_error_codes", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@system.command(
    name="wait",
    short_help="Blocking operation that will return when anchore-engine is available and ready",
)
@click.option(
    "--timeout",
    type=float,
    default=-1.0,
    help="Time to wait, in seconds. If < 0, wait forever (default=-1)",
)
@click.option(
    "--interval",
    type=float,
    default=5.0,
    help="Interval between checks, in seconds (default=5)",
)
@click.option(
    "--feedsready",
    default="vulnerabilities",
    help='In addition to API and set of core services being available, wait until at least one full feed sync has been completed for the CSV list of feeds (default="vulnerabilities").',
)
@click.option(
    "--servicesready",
    default="catalog,apiext,policy_engine,simplequeue,analyzer",
    help='Wait for the specified CSV list of anchore-engine services to have at least one service reporting as available (default="catalog,apiext,policy_engine,simplequeue,analyzer")',
)
def wait(timeout, interval, feedsready, servicesready):
    """
    Wait for an image to go to analyzed or analysis_failed status with a specific timeout

    :param timeout:
    :param interval:
    :param feedsready:
    :return:
    """
    global config
    ecode = 0

    try:
        sys.stderr.write(
            "Starting checks to wait for anchore-engine to be available timeout={} interval={}\n".format(
                timeout, interval
            )
        )
        ts = time.time()
        while timeout < 0 or time.time() - ts < timeout:
            _logger.debug(
                "Checking API availability for anchore-engine URL (%s)", config["url"]
            )
            # FIXME this can still break when formatting
            sys.stderr.write(
                "API availability: Checking anchore-engine URL ({})...\n".format(
                    config["url"]
                )
            )
            try:
                anchorecli.cli.utils.check_access(config)
                _logger.debug("check access success")
                break
            except Exception:
                _logger.debug("check access failed, trying again")
            time.sleep(interval)
        else:
            raise Exception("timed out after {} seconds.".format(timeout))

        sys.stderr.write("API availability: Success.\n")

        while timeout < 0 or time.time() - ts < timeout:
            all_up = {}
            try:
                services_to_check = [x for x in servicesready.split(",") if x]
                for f in services_to_check:
                    all_up[f] = False
            except:
                all_up = {}

            _logger.debug(
                "Checking service set availability for anchore-engine URL (%s)",
                config["url"],
            )
            # FIXME this can still break when formatting
            sys.stderr.write(
                "Service availability: Checking for service set ({})...\n".format(
                    ",".join(all_up.keys())
                )
            )
            try:
                ret = anchorecli.clients.apiexternal.system_status(config)
                ecode = anchorecli.cli.utils.get_ecode(ret)
                if ret["success"]:

                    for service_record in ret.get("payload", {}).get(
                        "service_states", []
                    ):
                        s = service_record.get("servicename", None)
                        if s:
                            if s not in all_up:
                                all_up[s] = False
                            try:
                                s_up = service_record.get("service_detail", {}).get(
                                    "up", False
                                )
                            except:
                                s_up = False
                            if s_up:
                                all_up[s] = s_up

                    if False not in all_up.values():
                        _logger.debug("full set of available engine services detected")
                        break
                    else:
                        _logger.debug("service set not yet available %s", all_up)
                elif ret.get("httpcode", 500) in [401]:
                    raise Exception(
                        "service responded with 401 Unauthorized - please check anchore-engine credentials and try again"
                    )
            except Exception as err:
                print("service status failed {}".format(err))
            time.sleep(interval)
        else:
            raise Exception("timed out after {} seconds.".format(timeout))
        sys.stderr.write("Service availability: Success.\n")

        if feedsready:
            all_up = {}
            try:
                feeds_to_check = feedsready.split(",")
                for f in feeds_to_check:
                    all_up[f] = False
            except:
                all_up = {}

            while timeout < 0 or time.time() - ts < timeout:
                _logger.debug(
                    "Checking feed sync status for anchore-engine URL (%s)",
                    config["url"],
                )
                # FIXME string substitution can still break this
                sys.stderr.write(
                    "Feed sync: Checking sync completion for feed set ({})...\n".format(
                        ",".join(all_up.keys())
                    )
                )
                try:
                    ret = anchorecli.clients.apiexternal.system_feeds_list(config)
                    if ret["success"]:
                        for feed_record in ret.get("payload", []):
                            _logger.debug(
                                "response shows feed name=%s was last_full_sync=%s",
                                feed_record.get("name"),
                                feed_record.get("last_full_sync"),
                            )
                            if feed_record.get("name", None) in all_up:
                                if not feed_record.get("enabled"):
                                    raise WaitOnDisabledFeedError(
                                        "Requesting wait for disabled feed: {}".format(
                                            feed_record.get("name")
                                        )
                                    )

                                if feed_record.get("last_full_sync", None):
                                    all_groups_synced = False
                                    for group_record in feed_record.get("groups", []):
                                        _logger.debug(
                                            "response shows group name=%s was last_sync=%s",
                                            group_record.get("name", None),
                                            group_record.get("last_sync", None),
                                        )
                                        if group_record.get(
                                            "last_sync", None
                                        ) or not group_record.get("enabled", None):
                                            all_groups_synced = True
                                        else:
                                            all_groups_synced = False
                                            break
                                    if all_groups_synced:
                                        all_up[feed_record.get("name")] = True

                        if False not in all_up.values():
                            _logger.debug("all requests feeds have been synced")
                            break
                        else:
                            _logger.debug("some feeds not yet synced %s", all_up)
                except WaitOnDisabledFeedError as err:
                    raise err
                except Exception as err:
                    print("service feeds list failed {}".format(err))
                time.sleep(interval)
            else:
                raise Exception("timed out after {} seconds.".format(timeout))

            sys.stderr.write("Feed sync: Success.\n")
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "system_wait", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@system.command(
    name="del", short_help="Delete a non-active service from anchore-engine"
)
@click.argument("host_id", nargs=1)
@click.argument("servicename", nargs=1)
def delete(host_id, servicename):
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.delete_system_service(
            config, host_id, servicename
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "delete_system_service", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "delete_system_service", {}, err
            )
        )
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
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "system_feeds_list", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "system_feeds_list", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@feeds.command(name="sync", short_help="Fetch latest updates from the feed service")
@click.option(
    "--flush",
    is_flag=True,
    help="Flush all previous data, including CVE matches, and resync from scratch",
)
def feedsync(flush):
    global input
    ecode = 0

    try:
        answer = "n"
        try:
            print(
                "\nWARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.\n"
            )
            try:
                input = raw_input
            except NameError:
                pass
            answer = input("Really perform a manual feed data sync/flush? (y/N)")
        except Exception:
            answer = "n"

        if "y" == answer.lower():
            ret = anchorecli.clients.apiexternal.system_feeds_sync(config, flush)
            ecode = anchorecli.cli.utils.get_ecode(ret)

            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "system_feeds_flush", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "system_feeds_flush", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@feeds.command(
    name="config",
    short_help="Enable a specific feed and or group so that it will sync data on the next sync",
)
@click.option("--group", help="Config a specific group only")
@click.option("--enable", help="Enable the feed/group", is_flag=True)
@click.option("--disable", help="Disable the feed/group", is_flag=True)
@click.argument("feed")
def toggle_enabled(feed, group=None, enable=None, disable=None):
    ecode = 0

    try:
        if not enable and not disable:
            raise Exception("Must set one of --enable or --disable")
        elif enable and disable:
            raise Exception("Can set only one of --enable or --disable")
        else:
            enabled = enable

        if group:
            ret = anchorecli.clients.apiexternal.system_feed_group_enable_toggle(
                config, feed, group, enabled=enabled
            )
            ecode = anchorecli.cli.utils.get_ecode(ret)
        else:
            ret = anchorecli.clients.apiexternal.system_feed_enable_toggle(
                config, feed, enabled=enabled
            )
            ecode = anchorecli.cli.utils.get_ecode(ret)

        if ret["success"]:
            if group:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "system_feed_groups", {}, [ret["payload"]]
                    )
                )
            else:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "system_feeds_list", {}, [ret["payload"]]
                    )
                )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "system_feeds_enable", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@feeds.command(
    name="delete",
    short_help="Delete the feed data for a feed or group. Metadata will remain but all feed data and vuln matches (if applicable) are removed",
)
@click.option("--group", help="Delete data for a specific group only")
@click.argument("feed")
def delete_data(feed, group=None):
    ecode = 0
    try:
        if group:
            ret = anchorecli.clients.apiexternal.system_feed_group_delete(
                config, feed, group
            )
            ecode = anchorecli.cli.utils.get_ecode(ret)
        else:
            ret = anchorecli.clients.apiexternal.system_feed_delete(config, feed)
            ecode = anchorecli.cli.utils.get_ecode(ret)

        if ret["success"]:
            if group:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "system_feed_groups", {}, [ret["payload"]]
                    )
                )
            else:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "system_feeds_list", {}, [ret["payload"]]
                    )
                )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "system_feeds_flush", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@system.group(name="webhook", short_help="For testing webhooks")
def webhook():
    pass


@webhook.command(name="test", short_help="Test that a given webhook works")
@click.argument("webhook_type", nargs=1, required=False)
@click.option(
    "--ntype",
    default="tag_update",
    help="The type of notification to send via the given webhook_type",
    required=False,
)
def test_webhook(webhook_type, ntype):
    """
    Call the Test Webhook Endpoint on Anchore Engine
    :param webhook_type: the type of webhook to send a test notification for
    """

    ecode = 0

    if not webhook_type:
        webhook_type = "general"

    try:
        _logger.debug(
            "Testing Webhook delivery for type '{}', notification_type '{}'".format(
                webhook_type, ntype
            )
        )
        ret = anchorecli.clients.apiexternal.test_webhook(config, webhook_type, ntype)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "test_webhook", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "test_webhook", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
