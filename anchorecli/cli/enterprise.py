import json
import sys

import click

import anchorecli.cli.utils
import anchorecli.clients.apiexternal

config = {}


@click.group(name="enterprise", short_help="Enterprise Anchore operations")
@click.pass_obj
def enterprise(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "image", {}, err))
        sys.exit(2)


@enterprise.group(
    name="corrections",
    short_help="Enterprise Anchore False-Positive Management Corrections",
)
@click.pass_obj
def corrections(ctx_config):
    pass


@corrections.command(
    name="add", short_help="Add a False-Positive Management Correction"
)
@click.option("--match", "-m", required=True, type=str, multiple=True)
@click.option("--package_type", "-p", required=True, type=str)
@click.option("--replace", "-r", required=True, type=str, multiple=True)
def add_correction(match, package_type, replace):
    """
    Add a False-Positive Management Correction for a package field
    Match and Replace arguments are key/value pairs, ex. "key=value"
    Match: package=spring-core
    Replace: cpes=cpe:2.3:a:pivotal_software:spring_framework:3.2.14:*:*:*:*:*:*:*

    Note, CPE replacement (shown above) supports templating based on package JSON fields, i.e.
        cpes=cpe:2.3:a:pivotal_software:{package}:3.2.14:*:*:*:*:*:*:*
    """
    error_code = 0
    try:
        normalized_match = {
            "type": package_type,
            "field_matches": normalize_correction_input(match),
        }
        normalized_replace = normalize_correction_input(replace)
        correction = {
            "type": "package",
            "match": normalized_match,
            "replace": normalized_replace,
        }
        ret = anchorecli.clients.apiexternal.enterprise_add_correction(
            config, correction
        )
        if ret:
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "add_correction", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "add_correction", {}, err)
        )
        if not error_code:
            error_code = 2
    anchorecli.cli.utils.doexit(error_code)


def normalize_correction_input(correction_input):
    normalized = []
    for item in correction_input:
        item_parts = item.split("=")
        if len(item_parts) != 2:
            raise Exception("Correction input is badly formed, cannot process")
        normalized.append({"field_name": item_parts[0], "field_value": item_parts[1]})
    return normalized


@corrections.command(
    name="get", short_help="Get a False-Positive Management Correction via UUID"
)
@click.argument("correction_id", nargs=1)
def get_correction(correction_id):
    """
    Correction ID: the UUID for a given correction
    """
    error_code = 0
    try:
        ret = anchorecli.clients.apiexternal.enterprise_get_correction(
            config, correction_id
        )
        if ret:
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "get_correction", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "get_correction", {}, err)
        )
        if not error_code:
            error_code = 2
    anchorecli.cli.utils.doexit(error_code)


@corrections.command(
    name="list", short_help="List all False-Positive Management Corrections"
)
def list_corrections():
    error_code = 0
    try:
        ret = anchorecli.clients.apiexternal.enterprise_list_corrections(config)
        if ret:
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "list_corrections", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "list_corrections", {}, err
            )
        )
        if not error_code:
            error_code = 2
    anchorecli.cli.utils.doexit(error_code)


@corrections.command(
    name="delete", short_help="Remove a False-Positive Management Correction"
)
@click.argument("correction_id", nargs=1)
def delete_correction(correction_id):
    """
    Correction ID: the UUID for a given correction
    """
    error_code = 0
    try:
        ret = anchorecli.clients.apiexternal.enterprise_delete_correction(
            config, correction_id
        )
        if ret:
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "delete_correction", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")
    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "delete_correction", {}, err
            )
        )
        if not error_code:
            error_code = 2
    anchorecli.cli.utils.doexit(error_code)
