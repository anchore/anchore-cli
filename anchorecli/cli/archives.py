import sys
import re
import json
import click

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}

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


@images.command(name='restore', short_help="Restore an image to active status from the archive")
@click.argument('image_digest')
def image_restore(image_digest):
    """
    Add an analyzed image to the analysis archive
    """
    ecode = 0

    try:
        if not re.match(digest_regex, image_digest):
            raise Exception('Invalid image digest {}. Must conform to regex: {}'.format(image_digest, digest_regex))

        ret = anchorecli.clients.apiexternal.restore_archived_image(config, image_digest)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'image_add', {}, ret['payload']))
        else:
            raise Exception( json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_add', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


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
        print(anchorecli.cli.utils.format_error_output(config, 'archive_analysis', {}, err))
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
                if ret['payload']:
                    result = [ret['payload']]
                else:
                    result = ret['payload']
                print(anchorecli.cli.utils.format_output(config, 'archived_analysis', {}, result))
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
@click.argument('days_old', type=click.IntRange(min=0))
@click.argument('tag_versions_newer', type=click.IntRange(min=0))
@click.argument('transition', type=click.Choice(['archive', 'delete']))
@click.option('--registry-selector', default='*', help="Registry to filter on, wildcard supported")
@click.option('--repository-selector', default='*', help="Repository to filter on, wildcard supported")
@click.option('--tag-selector', default='*', help="Tag to filter on, wildcard supported")
@click.option('--is-global', default=False, is_flag=True, help="If true, make this a global rule (admin only)")
def rule_add(days_old, tag_versions_newer, transition, registry_selector, repository_selector, tag_selector, is_global):
    """
    Add an analyzed image to the analysis archive

    DAYS_OLD: The minimum age of the image analysis or archive records to select

    TAG_VERSIONS_NEWER: the number of newer mappings of a tag to a digest that must exist for the tag to be selected by the rule

    archive|delete: the transition to execute - archive or delete. delete transitions occur on already archived analysis, not on the active image analysis

    """
    ecode = 0

    if days_old == 0 and tag_versions_newer == 0:
        resp = click.prompt('Are you sure you want to use 0 for both days old limit and number of tag versions newer? WARNING: This will archive all images that match the registry/repo/tag selectors as soon as they are analyzed', type=click.Choice(['y', 'n']), default='n')
        if resp.lower() != 'y':
            ecode = 0
            anchorecli.cli.utils.doexit(ecode)

    try:
        ret = anchorecli.clients.apiexternal.add_transition_rule(config, days_old, tag_versions_newer, registry_selector, repository_selector, tag_selector, transition, is_global)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print(anchorecli.cli.utils.format_output(config, 'transition_rules', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'transition_rules', {}, err))
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
        print(anchorecli.cli.utils.format_error_output(config, 'transition_rules', {}, err))
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
        print(anchorecli.cli.utils.format_error_output(config, 'transition_rules', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@rules.command(name='del', short_help="Delete a transition rule")
@click.argument('rule_id')
def rule_delete(rule_id):
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


