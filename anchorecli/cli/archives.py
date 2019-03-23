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


@click.group(name='analysis-archive', short_help='Archive operations')
@click.pass_obj
def archive(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image', {}, err))
        sys.exit(2)


@archive.group(name='images', short_help='Archive operations')
@click.pass_obj
def images(ctx_config):
    pass

@images.command(name='add', short_help="Add an image analysis to the archive")
@click.argument('image_digests', nargs=-1)
def image_add(image_digests):
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

@images.command(name='get', short_help="Get metadata for an archived image analysis")
@click.argument('digest', nargs=1)
def image_get(digest):
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

@images.command(name='list', short_help="List all archived image analyses")
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


@images.command(name='del', short_help="Delete an archived analysis")
@click.argument('digest')
@click.option('--force', is_flag=True, help="Force deletion of archived analysis")
def image_delete(digest, force):
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


# RULES operations

@archive.group(name='rules', short_help='Archive operations')
def rules():
    pass


@rules.command(name='add', short_help="Add a new transition rule")
@click.argument('analysis_age_days', type=int)
@click.argument('tag_versions_newer', type=int)
@click.argument('transition', type=click.Choice(['archive', 'delete']))
@click.option('--registry-selector', default='*', help="Registry to filter on, wildcard supported")
@click.option('--repository-selector', default='*', help="Repository to filter on, wildcard supported")
@click.option('--tag-selector', default='*', help="Tag to filter on, wildcard supported")
def rule_add(analysis_age_days, tag_versions_newer, transition, registry_selector, repository_selector, tag_selector):
    """
    Add an analyzed image to the analysis archive
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.add_transition_rule(config, analysis_age_days, tag_versions_newer, registry_selector, repository_selector, tag_selector, transition)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'transition_rules', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_add', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@rules.command(name='get', short_help="Show detail for a specific transition rule")
@click.argument('rule_id', nargs=1)
def rule_get(rule_id):
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_transition_rule(config, rule_id)

        if ret:
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'transition_rules', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'archived_analysis', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@rules.command(name='list', short_help="List all transition rules for the account")
def list_transition_rules():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.list_transition_rules(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'transition_rules', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'analysis_archive_list', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@rules.command(name='del', short_help="Delete a transition rule")
@click.argument('rule_id')
def rule_delete(rule_id):
    """
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.delete_transition_rule(config, rule_id)

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


