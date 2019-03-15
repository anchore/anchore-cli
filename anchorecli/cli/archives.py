import sys
import re
import json
import click
import logging

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}
_logger = logging.getLogger(__name__)

digest_regex = '^sha256:[abcdef0-9]+$'


@click.group(name='analysis_archive', short_help='Archive operations')
@click.pass_obj
def archive(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image', {}, err))
        sys.exit(2)


@archive.command(name='add', short_help="Add an image analysis to the archive")
@click.argument('image_digests', nargs=-1)
def add(image_digests):
    """
    Add an analyzed image to the analysis archive
    """
    ecode = 0

    try:
        for digest in image_digests:
            if not re.match(digest_regex, digest):
                raise Exception('Invalid image digest {}. Must conform to regex: {}'.format(digest, digest_regex))

        ret = anchorecli.clients.apiexternal.archive_analyses(config, image_digests)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'archive_analysis', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_add', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@archive.command(name='get', short_help="Get metadata for an archived image analysis")
@click.argument('digest', nargs=1)
def get(digest):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag
    """
    ecode = 0
    
    try:
        ret = anchorecli.clients.apiexternal.get_archived_analysis(config, digest)

        if ret:
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'archived_analysis', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'archived_analysis', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@archive.command(name='list', short_help="List all archived image analyses")
def list_archived_analyses():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.list_archived_analyses(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'analysis_archive_list', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'analysis_archive_list', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@archive.command(name='del', short_help="Delete an archived analysis")
@click.argument('digest')
@click.option('--force', is_flag=True, help="Force deletion of archived analysis")
def delete(digest, force):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag
    """
    ecode = 0
    
    try:
        ret = anchorecli.clients.apiexternal.delete_archived_analysis(config, digest)

        if ret:
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'image_delete', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_delete', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
