import pytest
from anchorecli.cli import archives
from click.testing import CliRunner


class TestArchiveSubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (archives.images, "Usage: images"),
            (archives.image_restore, "Usage: restore"),
            (archives.image_add, "Usage: add"),
            (archives.image_get, "Usage: get"),
            (archives.list_archived_analyses, "Usage: list"),
            (archives.image_delete, "Usage: del"),
            (archives.rules, "Usage: rules"),
            (archives.rule_add, "Usage: add"),
            (archives.rule_get, "Usage: get"),
            (archives.list_transition_rules, "Usage: list"),
            (archives.rule_delete, "Usage: del"),
        ]
    )
    def test_event_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
