import sys
import os
import re
import json
import click
import logging

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}
_logger = logging.getLogger(__name__)

@click.group(name='repo', short_help='Repository operations')
@click.pass_obj
def repo(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'repo', {}, err))
        sys.exit(2)

@repo.command(name='add', short_help="Add a repository")
@click.option('--noautosubscribe', is_flag=True, help="If set, instruct the engine to disable subscriptions for any discovered tags.")
@click.option('--lookuptag', help="Specify a tag to use for repo tag scan if 'latest' tag does not exist in the repo.")
@click.argument('input_repo', nargs=1)
def add(input_repo, noautosubscribe, lookuptag):
    """
    INPUT_REPO: Input repository can be in the following formats: registry/repo
    """
    ecode = 0

    autosubscribe = not noautosubscribe
    image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
    input_repo = image_info['registry'] + "/" + image_info['repo']

    try:
        ret = anchorecli.clients.apiexternal.add_repo(config, input_repo, autosubscribe=autosubscribe, lookuptag=lookuptag)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'repo_add', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'repo_add', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@repo.command(name='list', short_help="List added repositories")
def listrepos():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_repo(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'repo_list', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'repo_list', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@repo.command(name='get', short_help="Get a repository")
@click.argument('input_repo', nargs=1)
def get(input_repo):
    """
    INPUT_REPO: Input repository can be in the following formats: registry/repo
    """
    ecode = 0

    image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
    input_repo = image_info['registry'] + "/" + image_info['repo']
    
    try:
        ret = anchorecli.clients.apiexternal.get_repo(config, input_repo=input_repo)
        if ret:
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'repo_get', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'repo_get', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@repo.command(name='del', short_help="Delete a repository from the watch list (does not delete already analyzed images)")
@click.argument('input_repo', nargs=1)
def delete(input_repo):
    """
    INPUT_REPO: Input repo can be in the following formats: registry/repo
    """
    ecode = 0

    image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
    input_repo = image_info['registry'] + "/" + image_info['repo']
    
    try:
        ret = anchorecli.clients.apiexternal.delete_repo(config, input_repo)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret:
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'repo_delete', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'repo_delete', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@repo.command(name='unwatch', short_help="Instruct engine to stop automatically watching the repo for image updates")
@click.argument('input_repo', nargs=1)
def unwatch(input_repo):
    """
    INPUT_REPO: Input repo can be in the following formats: registry/repo
    """
    ecode = 0

    image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
    input_repo = image_info['registry'] + "/" + image_info['repo']
    
    try:
        ret = anchorecli.clients.apiexternal.unwatch_repo(config, input_repo)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret:
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'repo_unwatch', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'repo_unwatch', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@repo.command(name='watch', short_help="Instruct engine to start automatically watching the repo for image updates")
@click.argument('input_repo', nargs=1)
def watch(input_repo):
    """
    INPUT_REPO: Input repo can be in the following formats: registry/repo
    """
    ecode = 0

    image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
    input_repo = image_info['registry'] + "/" + image_info['repo']
    
    try:
        ret = anchorecli.clients.apiexternal.watch_repo(config, input_repo)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret:
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'repo_watch', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'repo_watch', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

