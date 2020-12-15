import pytest
from anchorecli.cli import policy
from click.testing import CliRunner


class TestPolicySubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (policy.add, "Usage: add"),
            (policy.get, "Usage: get"),
            (policy.policylist, "Usage: list"),
            (policy.activate, "Usage: activate"),
            (policy.delete, "Usage: del"),
            (policy.describe, "Usage: describe"),
            (policy.hub, "Usage: hub"),
            (policy.hublist, "Usage: list"),
            (policy.hubget, "Usage: get"),
            (policy.hubinstall, "Usage: install"),
        ]
    )
    def test_policy_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
