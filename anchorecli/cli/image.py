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

@click.group(name='image', short_help='Image operations')
@click.pass_obj
def image(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image', {}, err)
        sys.exit(2)

@image.command(name='add', short_help="Add an image")
@click.argument('input_image', nargs=1)
@click.option('--force', is_flag=True, help="Force reanalysis of image")
@click.option('--dockerfile', type=click.Path(exists=True), metavar='<Dockerfile>', help="Submit image's dockerfile for analysis")
def add(input_image, force, dockerfile):
    """
    INPUT_IMAGE: Input image can be in the following formats: registry/repo:tag
    """
    ecode = 0

    try:
        itype, image, urldigest = anchorecli.cli.utils.discover_inputimage(config, input_image)

        dockerfile_contents = None
        if dockerfile:
            with open(dockerfile, 'r') as FH:
                dockerfile_contents = FH.read().encode('base64')

        if itype == 'tag':
            ret = anchorecli.clients.apiexternal.add_image(config, tag=input_image, force=force, dockerfile=dockerfile_contents)
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print anchorecli.cli.utils.format_output(config, 'image_add', {}, ret['payload'])
            else:
                raise Exception( json.dumps(ret['error'], indent=4))
        else:
            raise Exception("can only add a tag")


    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image_add', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='import', short_help="Import an image from anchore scanner export")
@click.option('--infile', required=True, type=click.Path(exists=True), metavar='<file.json>')
def import_image(infile):
    ecode = 0

    try:
        with open(infile, 'r') as FH:
            anchore_data = json.loads(FH.read())

        ret = anchorecli.clients.apiexternal.import_image(config, anchore_data=anchore_data)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'image_import', {}, ret['payload'])
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image_import', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='get', short_help="Get an image")
@click.argument('input_image', nargs=1)
@click.option('--show-history', is_flag=True, help="Show history of images that match the input image, if input image is of the form registry/repo:tag")
def get(input_image, show_history):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag
    """
    ecode = 0
    
    try:
        itype, image, imageDigest = anchorecli.cli.utils.discover_inputimage(config, input_image)
        _logger.debug("discovery from input: " + str(itype) + " : " + str(image) + " : " + str(imageDigest))
        if itype == 'tag':
            ret = anchorecli.clients.apiexternal.get_image(config, tag=image, history=show_history)
        elif itype == 'digest':
            ret = anchorecli.clients.apiexternal.get_image(config, digest=image, imageDigest=imageDigest, history=False)
        elif itype == 'imageDigest':
            ret = anchorecli.clients.apiexternal.get_image(config, imageDigest=image, history=False)
        else:
            ecode = 1
            raise Exception("cannot use input image string: no discovered imageDigest")

        if ret:
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print anchorecli.cli.utils.format_output(config, 'image_get', {}, ret['payload'])
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image_get', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='list', short_help="List all images")
@click.option('--full', is_flag=True, help="Show full row output for each image")
@click.option('--show-all', is_flag=True, help="Show all images in the system instead of just the latest for a given tag")
def imagelist(full, show_all):
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_images(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret['success']:
            print anchorecli.cli.utils.format_output(config, 'image_list', {'full':full, 'show_all':show_all}, ret['payload'])
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image_list', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='content', short_help="Get contents of image")
@click.argument('input_image', nargs=1)
@click.argument('content_type', nargs=1, required=False)
def query_content(input_image, content_type):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag

    CONTENT_TYPE: The content type can be one of the following types: 

      - os: Operating System Packages

      - npm: Node.JS NPM Module

      - gem: Ruby GEM

      - files: Files
    """
    ecode = 0
    
    try:
        itype, image, imageDigest = anchorecli.cli.utils.discover_inputimage(config, input_image)
        _logger.debug("discovery from input: " + str(itype) + " : " + str(image) + " : " + str(imageDigest))

        if not imageDigest:
            ecode = 1
            raise Exception("cannot use input image string (no discovered imageDigest)")
        else:
            ret = anchorecli.clients.apiexternal.query_image(config, imageDigest=imageDigest, query_group='content', query_type=content_type)
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret:
                if ret['success']:
                    print anchorecli.cli.utils.format_output(config, 'image_content', {'query_type':content_type}, ret['payload'])
                else:
                    raise Exception (json.dumps(ret['error'], indent=4))
            else:
                raise Exception("operation failed with empty response")

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image_content', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='vuln', short_help="Get image vulnerabilities")
@click.argument('input_image', nargs=1)
@click.argument('vuln_type', nargs=1, required=False)
def query_vuln(input_image, vuln_type):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag
    
    VULN_TYPE: VULN_TYPE: Vulnerability type can be one of the following types: 

      - os: CVE/distro vulnerabilities against operating system packages
    """
    ecode = 0
    
    try:
        itype, image, imageDigest = anchorecli.cli.utils.discover_inputimage(config, input_image)

        if not imageDigest:
            ecode = 1
            raise Exception("cannot use input image string (no discovered imageDigest)")
        else:
            ret = anchorecli.clients.apiexternal.query_image(config, imageDigest=imageDigest, query_group='vuln', query_type=vuln_type)
            ecode = anchorecli.cli.utils.get_ecode(ret)

            if ret:
                if ret['success']:
                    print anchorecli.cli.utils.format_output(config, 'image_vuln', {'query_type':vuln_type}, ret['payload'])
                else:
                    raise Exception (json.dumps(ret['error'], indent=4))
            else:
                raise Exception("operation failed with empty response")

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image_vuln', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='del', short_help="Delete an image")
@click.argument('input_image', nargs=1)
@click.option('--force', is_flag=True, help="Force deletion of image by cancelling any subscription/notification settings prior to image delete")
def delete(input_image, force):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag
    """
    ecode = 0
    
    try:
        itype, image, imageDigest = anchorecli.cli.utils.discover_inputimage(config, input_image)

        if imageDigest:
            ret = anchorecli.clients.apiexternal.delete_image(config, imageDigest=imageDigest, force=force)
            ecode = anchorecli.cli.utils.get_ecode(ret)
        else:
            ecode = 1
            raise Exception("cannot use input image string: no discovered imageDigest")

        if ret:
            if ret['success']:
                print anchorecli.cli.utils.format_output(config, 'image_delete', {}, ret['payload'])
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print anchorecli.cli.utils.format_error_output(config, 'image_delete', {}, err)
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
