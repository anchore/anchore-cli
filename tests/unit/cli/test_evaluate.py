import pytest
from anchorecli.cli import evaluate
from click.testing import CliRunner


class TestEvaluateSubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (evaluate.check, "Usage: check"),
        ],
    )
    def test_event_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
