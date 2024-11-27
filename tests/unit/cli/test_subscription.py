import pytest
from anchorecli.cli import subscription
from click.testing import CliRunner


class TestSubscriptionSubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (subscription.activate, "Usage: activate"),
            (subscription.deactivate, "Usage: deactivate"),
            (subscription.list_subscriptions, "Usage: list"),
        ],
    )
    def test_subscription_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
