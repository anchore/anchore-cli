import sys
import json
import click

import anchorecli.clients.apiexternal

config = {}


@click.group(name="subscription", short_help="Subscription operations")
@click.pass_context
def subscription(ctx):
    def execute():
        global config
        config = ctx.parent.obj.config

        try:
            anchorecli.cli.utils.check_access(config)
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, "subscription", {}, err))
            sys.exit(2)

    ctx.obj = anchorecli.cli.utils.ContextObject(ctx.parent.obj.config, execute)


@subscription.command(name="activate", short_help="Activate a subscription")
@click.argument("subscription_type", nargs=1, required=True)
@click.argument("subscription_key", nargs=1, required=True)
@click.pass_context
def activate(ctx, subscription_type, subscription_key):
    """
    SUBSCRIPTION_TYPE: Type of subscription. Valid options:

      - tag_update: Receive notification when new image is pushed

      - policy_eval: Receive notification when image policy status changes

      - vuln_update: Receive notification when vulnerabilities are added, removed or modified

    SUBSCRIPTION_KEY: Fully qualified name of tag to subscribe to. Eg. docker.io/library/alpine:latest
    """
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        ret = anchorecli.clients.apiexternal.activate_subscription(
            config, subscription_type, subscription_key
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "subscription_activate", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "subscription_activate", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@subscription.command(name="deactivate", short_help="Deactivate a subscription")
@click.argument("subscription_type", nargs=1, required=True)
@click.argument("subscription_key", nargs=1, required=True)
@click.pass_context
def deactivate(ctx, subscription_type, subscription_key):
    """
    SUBSCRIPTION_TYPE: Type of subscription. Valid options:

      - tag_update: Receive notification when new image is pushed

      - policy_eval: Receive notification when image policy status changes

      - vuln_update: Receive notification when vulnerabilities are added, removed or modified

    SUBSCRIPTION_KEY: Fully qualified name of tag to subscribe to. Eg. docker.io/library/alpine:latest
    """
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        ret = anchorecli.clients.apiexternal.deactivate_subscription(
            config, subscription_type, subscription_key
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "subscription_deactivate", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "subscription_deactivate", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@subscription.command(name="list", short_help="List all current subscriptions")
@click.option(
    "--full",
    is_flag=True,
    help="Print additional details about the subscriptions as they're being listed",
)
@click.pass_context
def list_subscriptions(ctx, full):
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        ret = anchorecli.clients.apiexternal.get_subscription(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "subscription_list", {"full": full}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "subscription_list", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@subscription.command(
    name="get", short_help="Get details about a particular subscription"
)
@click.argument("subscription_id", nargs=1, required=True)
def get_subscription_by_id(subscription_id):
    return_code = 0
    try:
        ret = anchorecli.clients.apiexternal.get_subscription_by_id(
            config, subscription_id
        )
        return_code = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "subscription_get", {"full": True}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "subscription_get", {}, err
            )
        )
        if not return_code:
            return_code = 2

    anchorecli.cli.utils.doexit(return_code)


@subscription.command(
    name="del", short_help="Delete a subscription by ID (must be already deactivated)"
)
@click.argument("subscription_id", nargs=1, required=True)
def delete_subscription_by_id(subscription_id):
    return_code = 0
    try:
        ret = anchorecli.clients.apiexternal.delete_subscription_by_id(
            config, subscription_id
        )
        return_code = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print("Success")
        else:
            raise Exception(json.dumps(ret["error"], indent=4))
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "subscription_delete", {}, err
            )
        )
        if not return_code:
            return_code = 2

    anchorecli.cli.utils.doexit(return_code)
