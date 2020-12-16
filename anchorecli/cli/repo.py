import json
import sys

import click

import anchorecli.cli.utils
import anchorecli.clients.apiexternal

config = {}


@click.group(name="repo", short_help="Repository operations")
@click.pass_context
def repo(ctx):
    def execute():
        global config
        config = ctx.parent.obj.config

        try:
            anchorecli.cli.utils.check_access(config)
        except Exception as err:
            print(anchorecli.cli.utils.format_error_output(config, "repo", {}, err))
            sys.exit(2)

    ctx.obj = anchorecli.cli.utils.ContextObject(ctx.parent.obj.config, execute)


@repo.command(name="add", short_help="Add a repository")
@click.option(
    "--noautosubscribe",
    is_flag=True,
    help="If set, instruct the engine to disable subscriptions for any discovered tags.",
)
@click.option(
    "--lookuptag",
    help="Specify a tag to use for repo tag scan if 'latest' tag does not exist in the repo.",
)
@click.option(
    "--dryrun",
    is_flag=True,
    help="List which tags would actually be watched if this repo was added (without actually adding the repo)",
)
@click.argument("input_repo", nargs=1)
@click.pass_context
def add(ctx, input_repo, noautosubscribe, lookuptag, dryrun):
    """
    INPUT_REPO: Input repository can be in the following formats: registry/repo
    """
    response_code = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        autosubscribe = not noautosubscribe
        image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
        input_repo = image_info["registry"] + "/" + image_info["repo"]

        ret = anchorecli.clients.apiexternal.add_repo(
            config,
            input_repo,
            auto_subscribe=auto_subscribe,
            lookup_tag=lookuptag,
            dry_run=dryrun,
        )
        response_code = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "repo_add", {"dry_run": dryrun}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "repo_add", {}, err))
        if not response_code:
            response_code = 2

    anchorecli.cli.utils.doexit(response_code)


@repo.command(name="list", short_help="List added repositories")
@click.pass_context
def listrepos(ctx):
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        ret = anchorecli.clients.apiexternal.get_repo(config)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret["success"]:
            print(
                anchorecli.cli.utils.format_output(
                    config, "repo_list", {}, ret["payload"]
                )
            )
        else:
            raise Exception(json.dumps(ret["error"], indent=4))

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "repo_list", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@repo.command(name="get", short_help="Get a repository")
@click.argument("input_repo", nargs=1)
@click.pass_context
def get(ctx, input_repo):
    """
    INPUT_REPO: Input repository can be in the following formats: registry/repo
    """
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
        input_repo = image_info["registry"] + "/" + image_info["repo"]

        ret = anchorecli.clients.apiexternal.get_repo(config, input_repo=input_repo)
        if ret:
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "repo_get", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "repo_get", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@repo.command(
    name="del",
    short_help="Delete a repository from the watch list (does not delete already analyzed images)",
)
@click.argument("input_repo", nargs=1)
@click.pass_context
def delete(ctx, input_repo):
    """
    INPUT_REPO: Input repo can be in the following formats: registry/repo
    """
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
        input_repo = image_info["registry"] + "/" + image_info["repo"]

        ret = anchorecli.clients.apiexternal.delete_repo(config, input_repo)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret:
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "repo_delete", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "repo_delete", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@repo.command(
    name="unwatch",
    short_help="Instruct engine to stop automatically watching the repo for image updates",
)
@click.argument("input_repo", nargs=1)
@click.pass_context
def unwatch(ctx, input_repo):
    """
    INPUT_REPO: Input repo can be in the following formats: registry/repo
    """
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
        input_repo = image_info["registry"] + "/" + image_info["repo"]

        ret = anchorecli.clients.apiexternal.unwatch_repo(config, input_repo)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret:
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "repo_unwatch", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "repo_unwatch", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)


@repo.command(
    name="watch",
    short_help="Instruct engine to start automatically watching the repo for image updates",
)
@click.argument("input_repo", nargs=1)
@click.pass_context
def watch(ctx, input_repo):
    """
    INPUT_REPO: Input repo can be in the following formats: registry/repo
    """
    ecode = 0

    try:
        anchorecli.cli.utils.handle_parent_callback(ctx)

        image_info = anchorecli.cli.utils.parse_dockerimage_string(input_repo)
        input_repo = image_info["registry"] + "/" + image_info["repo"]

        ret = anchorecli.clients.apiexternal.watch_repo(config, input_repo)
        ecode = anchorecli.cli.utils.get_ecode(ret)
        if ret:
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config, "repo_watch", {}, ret["payload"]
                    )
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("operation failed with empty response")

    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "repo_watch", {}, err))
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
