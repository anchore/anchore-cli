import sys
import json
import click

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}


@click.group(name="query", short_help="Query operations")
@click.pass_context
def query(ctx):
    def execute():
        global config
        config = ctx.parent.obj.config

        try:
            anchorecli.cli.utils.check_access(config)
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, "query", {}, err))
            sys.exit(2)

    ctx.obj = anchorecli.cli.utils.ContextObject(ctx.parent.obj.config, execute)


@query.command(
    name="images-by-vulnerability",
    short_help="Search system for images with the given vulnerability ID present",
)
@click.option(
    "--vulnerability-id",
    required=True,
    help="Search for images vulnerable to this vulnerability ID (e.g. CVE-1999-0001)",
)
@click.option(
    "--namespace",
    help="Filter results to images with vulnerable packages in the given namespace (e.g. debian:9)",
)
@click.option(
    "--package",
    help="Filter results to images with the given vulnerable package name (e.g. sed)",
)
@click.option(
    "--severity",
    help="Filter results to images with the given vulnerability severity (e.g. Medium)",
)
@click.option(
    "--vendor_only",
    is_flag=True,
    help="Only show images with vulnerabilities explicitly deemed applicable by upstream OS vendor, if present",
)
@click.pass_context
def images_by_vulnerability(
    ctx, vulnerability_id, namespace, package, severity, vendor_only
):
    """"""
    ctx.parent.obj.execute_callback()

    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        ret = anchorecli.clients.apiexternal.query_images_by_vulnerability(
            config,
            vulnerability_id,
            namespace=namespace,
            affected_package=package,
            severity=severity,
            vendor_only=vendor_only,
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config,
                    "query_images_by_vulnerability",
                    {"vulnerability_id": vulnerability_id},
                    ret["payload"],
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "query_images_by_vulnerability", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@query.command(
    name="images-by-package",
    short_help="Search system for images with the given package installed",
)
@click.option(
    "--name", required=True, help="Search for images with this package name (e.g. sed)"
)
@click.option(
    "--version", help="Filter results to only packages with given version (e.g. 4.4-1)"
)
@click.option(
    "--package-type", help="Filter results to only packages of given type (e.g. dpkg)"
)
@click.pass_context
def images_by_package(ctx, name, version, package_type):
    """"""
    ctx.parent.obj.execute_callback()
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        ret = anchorecli.clients.apiexternal.query_images_by_package(
            config, name, version=version, package_type=package_type
        )
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "query_images_by_package", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(
                config, "query_images_by_package", {}, err
            )
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
