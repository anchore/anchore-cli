import click
import logging

from . import (
    image,
    policy,
    evaluate,
    subscription,
    registry,
    system,
    utils,
    repo,
    event,
    query,
    account,
    archives,
    enterprise,
)

from anchorecli import version
import anchorecli.clients  # noqa


@click.group(context_settings=dict(help_option_names=["-h", "--help", "help"]))
@click.option(
    "--config", help="Set the location of the anchore-cli yaml configuration file"
)
@click.option("--debug", is_flag=True, help="Debug output to stderr")
@click.option("--u", help="Username (or use environment variable ANCHORE_CLI_USER)")
@click.option("--p", help="Password (or use environment variable ANCHORE_CLI_PASS)")
@click.option("--url", help="Service URL (or use environment variable ANCHORE_CLI_URL)")
@click.option(
    "--hub-url",
    help="Anchore Hub URL (or use environment variable ANCHORE_CLI_HUB_URL)",
)
@click.option(
    "--api-version",
    help="Explicitly specify the API version to skip checking. Useful when swagger endpoint is inaccessible",
)
@click.option(
    "--insecure",
    is_flag=True,
    help="Skip SSL cert checks (or use environment variable ANCHORE_CLI_SSL_VERIFY=<y/n>)",
)
@click.option("--json", is_flag=True, help="Output raw API JSON")
@click.option(
    "--as-account",
    help="Set account context for the command to another account than the one the user belongs to. Subject to authz",
    default=None,
)
@click.version_option(version=version.version)
@click.pass_context
def main_entry(
    ctx, debug, config, u, p, url, hub_url, api_version, insecure, json, as_account
):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    cli_opts = {
        "config": config,
        "u": u,
        "p": p,
        "url": url,
        "hub-url": hub_url,
        "api-version": api_version,
        "insecure": insecure,
        "json": json,
        "debug": debug,
        "as_account": as_account,
    }

    config = utils.setup_config(cli_opts)
    if config["debug"]:
        logging.basicConfig(level=logging.DEBUG)

    ctx.obj = config


class Help(click.Command):
    """
    Do not parse any arguments, allow any args past the `help` command,
    always return the help output
    """

    def parse_args(self, ctx, args):
        return []


@click.command(cls=Help)
@click.pass_context
def help(ctx):
    print(ctx.parent.get_help())


main_entry.add_command(help)
main_entry.add_command(image.image)
main_entry.add_command(evaluate.evaluate)
main_entry.add_command(policy.policy)
main_entry.add_command(subscription.subscription)
main_entry.add_command(registry.registry)
main_entry.add_command(repo.repo)
main_entry.add_command(system.system)
main_entry.add_command(event.event)
main_entry.add_command(query.query)
main_entry.add_command(account.account)
main_entry.add_command(archives.archive)
main_entry.add_command(enterprise.enterprise)
# main_entry.add_command(interactive.interactive)
