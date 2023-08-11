import pytest
from anchorecli.cli import account
from click.testing import CliRunner


class TestAccountSubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (account.get_current_user, "Usage: whoami"),
            (account.add, "Usage: add"),
            (account.get, "Usage: get"),
            (account.list_accounts, "Usage: list"),
            (account.delete, "Usage: del"),
            (account.enable, "Usage: enable"),
            (account.disable, "Usage: disable"),
            (account.user, "Usage: user"),
            (account.user_add, "Usage: add"),
            (account.user_delete, "Usage: del"),
            (account.user_get, "Usage: get"),
            (account.user_list, "Usage: list"),
            (account.user_setpassword, "Usage: setpassword"),
        ],
    )
    def test_event_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
