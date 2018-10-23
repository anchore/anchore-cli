import sys
import os
import re
import json
import click

import anchorecli.clients.apiexternal

config = {}
whoami = {}

@click.group(name='account', short_help='Account operations')
@click.pass_obj
def account(ctx_config):
    global config, whoami
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account', {}, err))
        sys.exit(2)

    try:
        ret = anchorecli.clients.apiexternal.get_account(config)
        if ret['success']:
            whoami['account'] = ret['payload']
        else:
            raise Exception( json.dumps(ret['error'], indent=4))
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account', {}, err))
        sys.exit(2)

    try:
        ret = anchorecli.clients.apiexternal.get_user(config)
        if ret['success']:
            whoami['user'] = ret['payload']
        else:
            raise Exception( json.dumps(ret['error'], indent=4))
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account', {}, err))
        sys.exit(2)


@account.command(name='whoami', short_help="Get current account/user information")
def whoami():
    global whoami
    ecode = 0
    print(anchorecli.cli.utils.format_output(config, 'account_whoami', {}, whoami))
    anchorecli.cli.utils.doexit(ecode)


@account.command(name='add', short_help="Add a new account (with no populated users by default)")
@click.argument('account_name', nargs=1, required=True)
@click.option('--email', help="Optional email address to associate with account")
def add(account_name, email):
    """
    ACCOUNT_NAME: name of new account to create

    EMAIL: email address associated with account (optional)

    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.add_account(config, account_name=account_name, email=email)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'account_add', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account_add', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name='get', short_help="Get account information")
@click.argument('account_name', nargs=1, required=True)
def get(account_name):
    """
    ACCOUNT_NAME: name of new account to create

    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_account(config, account_name=account_name)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'account_get', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account_get', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name='list', short_help="List information about all accounts (admin only)")
def list_accounts():
    """
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.list_accounts(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'account_list', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account_list', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name='del', short_help="Delete an account (must be deactivated first)")
@click.argument('account_name', nargs=1, required=True)
def delete(account_name):
    """
    ACCOUNT_NAME: name of account to delete (must be deactivated first)

    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.del_account(config, account_name=account_name)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'account_delete', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account_delete', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name='activate', short_help="Activate a deactivated account")
@click.argument('account_name', nargs=1, required=True)
def activate(account_name):
    """
    ACCOUNT_NAME: name of account to activate

    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.activate_account(config, account_name=account_name)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'account_activate', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account_activate', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@account.command(name='deactivate', short_help="Deactivate an activated account")
@click.argument('account_name', nargs=1, required=True)
def deactivate(account_name):
    """
    ACCOUNT_NAME: name of account to deactivate

    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.deactivate_account(config, account_name=account_name)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'account_deactivate', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'account_deactivate', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

# user suboperation

whoami = {}
@account.group(name="user", short_help="Account user operations")
def user():
    global config, whoami


@user.command(name="add", short_help="Add a new user")
@click.argument('user_name', nargs=1, required=True)
@click.argument('user_password', nargs=1, required=True)
@click.option('--account', help="Optional account name")
def user_add(user_name, user_password, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """

    if not account:
        account = whoami.get('account', {}).get('name', None)
        
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.add_user(config, account_name=account, user_name=user_name, user_password=user_password)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'user_add', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'user_add', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="del", short_help="Delete a user")
@click.argument('user_name', nargs=1, required=True)
@click.option('--account', help="Optional account name")
def user_delete(user_name, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """

    if not account:
        account = whoami.get('account', {}).get('name', None)
        
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.del_user(config, account_name=account, user_name=user_name)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'user_delete', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'user_delete', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="get", short_help="Get information about a user")
@click.argument('user_name', nargs=1, required=True)
@click.option('--account', help="Optional account name")
def user_get(user_name, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """

    if not account:
        account = whoami.get('account', {}).get('name', None)
        
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_user(config, account_name=account, user_name=user_name)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'user_get', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'user_get', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="list", short_help="Get a list of account users")
@click.option('--account', help="Optional account name")
def user_list(account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """

    if not account:
        account = whoami.get('account', {}).get('name', None)
        
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.list_users(config, account_name=account)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'user_list', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'user_list', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@user.command(name="setpassword", short_help="(Re)set a user's password credential")
@click.argument('user_password', nargs=1, required=True)
@click.option('--username', help="Optional user name")
@click.option('--account', help="Optional account name")
def user_setpassword(user_password, username, account):
    global whoami
    """
    ACCOUNT: optional name of the account to act as

    """

    if not account:
        account = whoami.get('account', {}).get('name', None)
    if not username:
        username = whoami.get('user', {}).get('username', None)

    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.update_user_password(config, account_name=account, user_name=username, user_password=user_password)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'user_setpassword', {}, ret['payload']))
            print ("NOTE: Be sure to change the password you're using for this client if you have reset your own password")
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'user_setpassword', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
    

