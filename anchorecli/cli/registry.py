import sys
import re
import json
import click

import anchorecli.clients.apiexternal

config = {}


@click.group(name="registry", short_help="Registry operations")
@click.pass_obj
def registry(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "registry", {}, err))
        sys.exit(2)


@registry.command(name="add", short_help="Add a registry")
@click.argument("registry", nargs=1, required=True)
@click.argument("registry_user", nargs=1, required=True)
@click.argument("registry_pass", nargs=1, required=True)
@click.option(
    "--insecure",
    is_flag=True,
    default=False,
    help="Allow connection to registry without SSL cert checks (ex: if registry uses a self-signed SSL certificate)",
)
@click.option("--registry-type", help="Specify the registry type (default='docker_v2')")
@click.option(
    "--skip-validate",
    is_flag=True,
    help="Do not attempt to validate registry/creds on registry add",
)
@click.option(
    "--registry-name",
    help="Specify a human name for this registry (default=same as 'registry')",
)
def add(
    registry,
    registry_user,
    registry_pass,
    insecure,
    registry_type,
    skip_validate,
    registry_name,
):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000

    REGISTRY_USER: Username

    REGISTRY_PASS: Password
    """
    ecode = 0

    registry_types = ["docker_v2", "awsecr"]

    try:
        if registry_type and registry_type not in registry_types:
            raise Exception(
                "input registry type not supported (supported registry_types: "
                + str(registry_types)
            )

        # try to detect awsecr registry of form <accid>.dkr.ecr.<region>.amazonaws.com
        if not registry_type:
            if re.match("[0-9]+\.dkr\.ecr\..*\.amazonaws\.com", registry):
                sys.stderr.write(
                    "WARN: setting registry type to 'awsecr' based on form of input registry name, remove and re-add using '--registry-type docker_v2' to override\n"
                )
                registry_type = "awsecr"
            else:
                registry_type = "docker_v2"

        if not registry_name:
            registry_name = registry

        ret = anchorecli.clients.apiexternal.add_registry(
            config,
            registry=registry,
            registry_user=registry_user,
            registry_pass=registry_pass,
            registry_type=registry_type,
            insecure=insecure,
            validate=(not skip_validate),
            registry_name=registry_name,
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "registry_add", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "registry_add", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@registry.command(name="update", short_help="Update an existing registry")
@click.argument("registry", nargs=1, required=True)
@click.argument("registry_user", nargs=1, required=True)
@click.argument("registry_pass", nargs=1, required=True)
@click.option(
    "--insecure",
    is_flag=True,
    default=False,
    help="Allow connection to registry without SSL cert checks (ex: if registry uses a self-signed SSL certificate)",
)
@click.option(
    "--registry-type",
    default="docker_v2",
    help="Specify the registry type (default='docker_v2')",
)
@click.option(
    "--skip-validate",
    is_flag=True,
    help="Do not attempt to validate registry/creds on registry add",
)
@click.option(
    "--registry-name",
    help="Specify a human name for this registry (default=same as 'registry')",
)
def upd(
    registry,
    registry_user,
    registry_pass,
    insecure,
    registry_type,
    skip_validate,
    registry_name,
):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000

    REGISTRY_USER: Username

    REGISTRY_PASS: Password
    """
    ecode = 0

    try:
        if not registry_name:
            registry_name = registry

        ret = anchorecli.clients.apiexternal.update_registry(
            config,
            registry=registry,
            registry_user=registry_user,
            registry_pass=registry_pass,
            registry_type=registry_type,
            insecure=insecure,
            validate=(not skip_validate),
            registry_name=registry_name,
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "registry_update", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "registry_update", {}, err)
        )
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)


@registry.command(name="del", short_help="Delete a registry")
@click.argument("registry", nargs=1, required=True)
def delete(registry):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.delete_registry(config, registry)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "registry_delete", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "registry_delete", {}, err)
        )
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)


@registry.command(name="list", short_help="List all current registries")
def registrylist():
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_registry(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "registry_list", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "registry_list", {}, err)
        )
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)


@registry.command(name="get", short_help="Get a registry")
@click.argument("registry", nargs=1, required=True)
def get(registry):
    """
    REGISTRY: Full hostname/port of registry. Eg. myrepo.example.com:5000
    """
    ecode = 0

    try:
        ret = anchorecli.clients.apiexternal.get_registry(config, registry=registry)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "registry_get", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "registry_get", {}, err))
        if not ecode:
            ecode = 2
    anchorecli.cli.utils.doexit(ecode)
