import sys
import re
import json
import click

import anchorecli.clients.apiexternal

config = {}
whoami = {}


@click.group(name="account", short_help="Account operations")
@click.pass_context
def account(ctx):
    def execute():
        global config, whoami
        config = ctx.parent.obj.config

        try:
            anchorecli.cli.utils.check_access(config)
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, "account", {}, err))
            sys.exit(2)

        try:
            ret = anchorecli.clients.apiexternal.get_account(config)
            if ret["success"]:
                whoami["account"] = ret["payload"]
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, "account", {}, err))
            sys.exit(2)

        try:
            ret = anchorecli.clients.apiexternal.get_user(config)
            if ret["success"]:
                whoami["user"] = ret["payload"]
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, "account", {}, err))
            sys.exit(2)

    ctx.obj = anchorecli.cli.utils.ContextObject(ctx.parent.obj.config, execute)


@account.command(name="whoami", short_help="Get current account/user information")
@click.pass_context
def get_current_user(ctx):
    global whoami

    ctx.parent.obj.execute_callback()

    ecode = 0
    print(anchorecli.cli.utils.format_output(config, "account_whoami", {}, whoami))
    anchorecli.cli.utils.doexit(ecode)


@account.command(
    name="add", short_help="Add a new account (with no populated users by default)"
)
@click.argument("account_name", nargs=1, required=True)
@click.option("--email", help="Optional email address to associate with account")
@click.pass_context
def add(ctx, account_name, email):
    """
    ACCOUNT_NAME: name of new account to create

    EMAIL: email address associated with account (optional)

    """
    ctx.parent.obj.execute_callback()

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.add_account(
            config, account_name=account_name, email=email
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "account_add", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "account_add", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name="get", short_help="Get account information")
@click.argument("account_name", nargs=1, required=True)
@click.pass_context
def get(ctx, account_name):
    """
    ACCOUNT_NAME: name of new account to create

    """
    ctx.parent.obj.execute_callback()

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_account(
            config, account_name=account_name
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "account_get", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "account_get", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(
    name="list", short_help="List information about all accounts (admin only)"
)
@click.pass_context
def list_accounts(ctx):
    """"""
    ctx.parent.obj.execute_callback()

    ecode = 0
    try:
        ret = anchorecli.clients.apiexternal.list_accounts(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "account_list", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "account_list", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name="del", short_help="Delete an account (must be disabled first)")
@click.argument("account_name", nargs=1, required=True)
@click.option(
    "--dontask", is_flag=True, help="Do not prompt for confirmation of account deletion"
)
@click.pass_context
def delete(ctx, account_name, dontask):
    global input
    """
    ACCOUNT_NAME: name of account to delete (must be disabled first)

    """
    ctx.parent.obj.execute_callback()

    ecode = 0

    answer = "n"
    if dontask:
        answer = "y"
    else:
        try:
            input = raw_input
        except NameError:
            pass
        try:
            answer = input(
                "This operation is irreversible. Really delete account {} along with *all* users and resources associated with this account? (y/N)".format(
                    account_name
                )
            )
        except:
            answer = "n"

    if answer.lower() == "y":
        try:
            ret = anchorecli.clients.apiexternal.del_account(
                config, account_name=account_name
            )
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "account_delete", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))

        except Exception as err:
            print(
                anchorecli.cli.utils.format_error_output(
                    config, "account_delete", {}, err
                )
            )
            if not ecode:
                ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name="enable", short_help="Enable a disabled account")
@click.argument("account_name", nargs=1, required=True)
@click.pass_context
def enable(ctx, account_name):
    """
    ACCOUNT_NAME: name of account to enable

    """
    ctx.parent.obj.execute_callback()

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.enable_account(
            config, account_name=account_name
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "account_enable", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "account_enable", {}, err)
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name="disable", short_help="Disable an enabled account")
@click.argument("account_name", nargs=1, required=True)
@click.pass_context
def disable(ctx, account_name):
    """
    ACCOUNT_NAME: name of account to disable

    """
    ctx.parent.obj.execute_callback()

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.disable_account(
            config, account_name=account_name
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "account_disable", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "account_disable", {}, err)
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


# user suboperation


@account.group(name="user", short_help="Account user operations")
@click.pass_context
def user(ctx):
    global config, whoami

    # since there's nothing to execute here, just pass the parent config and callback down
    ctx.obj = anchorecli.cli.utils.ContextObject(ctx.parent.obj.config, ctx.parent.obj.execute_callback)


@user.command(name="add", short_help="Add a new user")
@click.argument("user_name", nargs=1, required=True)
@click.argument("user_password", nargs=1, required=True)
@click.option("--account", help="Optional account name")
@click.pass_context
def user_add(ctx, user_name, user_password, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """
    ctx.parent.obj.execute_callback()

    if not account:
        account = whoami.get("account", {}).get("name", None)

    ecode = 0

    try:
        # do some input validation
        if not re.match(".{6,128}$", user_password):
            raise Exception(
                "Please enter a password at least 6 characters long that contains no spaces."
            )

        ret = anchorecli.clients.apiexternal.add_user(
            config,
            account_name=account,
            user_name=user_name,
            user_password=user_password,
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "user_add", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "user_add", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="del", short_help="Delete a user")
@click.argument("user_name", nargs=1, required=True)
@click.option("--account", help="Optional account name")
@click.pass_context
def user_delete(ctx, user_name, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """
    ctx.parent.obj.execute_callback()

    if not account:
        account = whoami.get("account", {}).get("name", None)

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.del_user(
            config, account_name=account, user_name=user_name
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "user_delete", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "user_delete", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="get", short_help="Get information about a user")
@click.argument("user_name", nargs=1, required=True)
@click.option("--account", help="Optional account name")
@click.pass_context
def user_get(ctx, user_name, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """
    ctx.parent.obj.execute_callback()

    if not account:
        account = whoami.get("account", {}).get("name", None)

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_user(
            config, account_name=account, user_name=user_name
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "user_get", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "user_get", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="list", short_help="Get a list of account users")
@click.option("--account", help="Optional account name")
@click.pass_context
def user_list(ctx, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """
    ctx.parent.obj.execute_callback()

    if not account:
        account = whoami.get("account", {}).get("name", None)

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.list_users(config, account_name=account)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "user_list", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "user_list", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="setpassword", short_help="(Re)set a user's password credential")
@click.argument("user_password", nargs=1, required=True)
@click.option("--username", help="Optional user name")
@click.option("--account", help="Optional account name")
@click.pass_context
def user_setpassword(ctx, user_password, username, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """
    ctx.parent.obj.execute_callback()

    if not account:
        account = whoami.get("account", {}).get("name", None)
    if not username:
        username = whoami.get("user", {}).get("username", None)

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.update_user_password(
            config,
            account_name=account,
            user_name=username,
            user_password=user_password,
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "user_setpassword", {}, ret["payload"]
                )
            )
            print(
                "NOTE: Be sure to change the password you're using for this client if you have reset your own password"
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "user_setpassword", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
