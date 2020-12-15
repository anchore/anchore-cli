import pytest
from anchorecli.cli import repo
from click.testing import CliRunner


class TestRepoSubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (repo.add, "Usage: add"),
            (repo.listrepos, "Usage: list"),
            (repo.get, "Usage: get"),
            (repo.delete, "Usage: del"),
            (repo.unwatch, "Usage: unwatch"),
            (repo.watch, "Usage: watch"),
        ]
    )
    def test_repo_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
