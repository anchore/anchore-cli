import pytest
from anchorecli.cli import registry
from click.testing import CliRunner


class TestRegistrySubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (registry.add, "Usage: add"),
            (registry.upd, "Usage: update"),
            (registry.delete, "Usage: del"),
            (registry.registrylist, "Usage: list"),
            (registry.get, "Usage: get"),
        ],
    )
    def test_registry_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
