import pytest
from anchorecli.cli import query
from click.testing import CliRunner


class TestQuerySubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (query.images_by_vulnerability, "Usage: images-by-vulnerability"),
            (query.images_by_package, "Usage: images-by-package"),
        ]
    )
    def test_query_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
