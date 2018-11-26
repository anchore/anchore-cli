import sys
import os
import re
import json
import click
import logging
import time

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
        print(anchorecli.cli.utils.format_error_output(config, 'image', {}, err))
        sys.exit(2)


@image.command(short_help="Wait for an image to analyze")
@click.argument('input_image')
@click.option('--timeout', type=float, default=-1.0, help="Time to wait, in seconds.  If < 0, wait forever, if 0, do not wait (default=-1)")
@click.option('--interval', type=float, default=5.0, help="Interval between checks, in seconds (default=5)")
def wait(input_image, timeout, interval):
    """
    Wait for an image to go to analyzed or analysis_failed status with a specific timeout

    :param input_image:
    :param timeout:
    :return:
    """
    ecode = 0

    try:
        itype = anchorecli.cli.utils.discover_inputimage_format(config, input_image)
        image = input_image
        #timeout = float(timeout)
        t1 = time.time()
        while timeout < 0 or time.time() - t1 < timeout:
            _logger.debug("discovery from input: " + str(itype) + " : " + str(image))
            if itype == 'tag':
                ret = anchorecli.clients.apiexternal.get_image(config, tag=image, history=False)
            elif itype == 'imageid':
                ret = anchorecli.clients.apiexternal.get_image(config, image_id=image, history=False)
            elif itype == 'imageDigest':
                ret = anchorecli.clients.apiexternal.get_image(config, imageDigest=image, history=False)
            else:
                ecode = 1
                raise Exception("cannot use input image string: no discovered imageDigest")

            if ret['payload'] and ret['payload'][0]['analysis_status'] in ['analyzed', 'analysis_failed']:
                break
            else:
                if not ret['payload']:
                    raise Exception('Requested image not found in system')
                print('Status: {}'.format(ret['payload'][0]['analysis_status']))

            if timeout > 0:
                print('Waiting {} seconds for next retry. Total timeout remaining: {}'.format(interval, int(timeout - (time.time() - t1))))
            else:
                print('Waiting {} seconds for next retry.'.format(interval))

            time.sleep(interval)
        else:
            raise Exception('Timed-out waiting for analyis status to reach terminal state (analyzed or analysis_failed)')

        if ret:
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'image_get', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_get', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@image.command(name='add', short_help="Add an image")
@click.argument('input_image', nargs=1)
@click.option('--force', is_flag=True, help="Force reanalysis of image")
@click.option('--dockerfile', type=click.Path(exists=True), metavar='<Dockerfile>', help="Submit image's dockerfile for analysis")
@click.option('--annotation', nargs=1, multiple=True)
@click.option('--noautosubscribe', is_flag=True, help="If set, instruct the engine to disable tag_update subscription for the added tag.")
def add(input_image, force, dockerfile, annotation, noautosubscribe):
    """
    INPUT_IMAGE: Input image can be in the following formats: registry/repo:tag
    """
    ecode = 0

    try:
        itype = anchorecli.cli.utils.discover_inputimage_format(config, input_image)

        dockerfile_contents = None
        if dockerfile:
            with open(dockerfile, 'r') as FH:
                dockerfile_contents = FH.read().encode('base64')

        autosubscribe = not noautosubscribe

        if itype == 'tag':
            annotations = {}
            if annotation:
                for a in annotation:
                    try:
                        (k,v) = a.split('=', 1)
                        if k and v:
                            annotations[k] = v
                        else:
                            raise Exception("found null in key or value")
                    except Exception as err:
                        raise Exception("annotation format error - annotations must be of the form (--annotation key=value), found: {}".format(a))

            ret = anchorecli.clients.apiexternal.add_image(config, tag=input_image, force=force, dockerfile=dockerfile_contents, annotations=annotations, autosubscribe=autosubscribe)
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'image_add', {}, ret['payload']))
            else:
                raise Exception( json.dumps(ret['error'], indent=4))
        else:
            raise Exception("can only add a tag")


    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_add', {}, err))
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
            print(anchorecli.cli.utils.format_output(config, 'image_import', {}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_import', {}, err))
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
        itype = anchorecli.cli.utils.discover_inputimage_format(config, input_image)
        image = input_image

        _logger.debug("discovery from input: " + str(itype) + " : " + str(image))
        if itype == 'tag':
            ret = anchorecli.clients.apiexternal.get_image(config, tag=image, history=show_history)
        elif itype == 'imageid':
            ret = anchorecli.clients.apiexternal.get_image(config, image_id=image, history=False)
        elif itype == 'imageDigest':
            ret = anchorecli.clients.apiexternal.get_image(config, imageDigest=image, history=False)
        else:
            ecode = 1
            raise Exception("cannot use input image string: no discovered imageDigest")

        if ret:
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret['success']:
                print(anchorecli.cli.utils.format_output(config, 'image_get', {}, ret['payload']))
            else:
                raise Exception(json.dumps(ret['error'], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_get', {}, err))
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
            print(anchorecli.cli.utils.format_output(config, 'image_list', {'full':full, 'show_all':show_all}, ret['payload']))
        else:
            raise Exception(json.dumps(ret['error'], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_list', {}, err))
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
                    print(anchorecli.cli.utils.format_output(config, 'image_content', {'query_type':content_type}, ret['payload']))
                else:
                    raise Exception (json.dumps(ret['error'], indent=4))
            else:
                raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_content', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='metadata', short_help="Get metadata about an image")
@click.argument('input_image', nargs=1)
@click.argument('metadata_type', nargs=1, required=False)
def query_metadata(input_image, metadata_type):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag

    METADATA_TYPE: The metadata type can be one of the types returned by running without a type specified

    """
    ecode = 0
    
    try:
        itype, image, imageDigest = anchorecli.cli.utils.discover_inputimage(config, input_image)
        _logger.debug("discovery from input: " + str(itype) + " : " + str(image) + " : " + str(imageDigest))

        if not imageDigest:
            ecode = 1
            raise Exception("cannot use input image string (no discovered imageDigest)")
        else:
            ret = anchorecli.clients.apiexternal.query_image(config, imageDigest=imageDigest, query_group='metadata', query_type=metadata_type)
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret:
                if ret['success']:
                    print(anchorecli.cli.utils.format_output(config, 'image_metadata', {'query_type':metadata_type}, ret['payload']))
                else:
                    raise Exception (json.dumps(ret['error'], indent=4))
            else:
                raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_metadata', {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)

@image.command(name='vuln', short_help="Get image vulnerabilities")
@click.argument('input_image', nargs=1)
@click.argument('vuln_type', nargs=1, required=False)
@click.option('--vendor-only', default=True, type=bool, help="Show only vulnerabilities marked by upstream vendor as applicable (default=True)")
def query_vuln(input_image, vuln_type, vendor_only):
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
            ret = anchorecli.clients.apiexternal.query_image(config, imageDigest=imageDigest, query_group='vuln', query_type=vuln_type, vendor_only=vendor_only)
            ecode = anchorecli.cli.utils.get_ecode(ret)

            if ret:
                if ret['success']:
                    print(anchorecli.cli.utils.format_output(config, 'image_vuln', {'query_type':vuln_type}, ret['payload']))
                else:
                    raise Exception (json.dumps(ret['error'], indent=4))
            else:
                raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, 'image_vuln', {}, err))
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
