from conftest import call, ExitCode
import json
import pytest


@pytest.mark.parametrize(
    "sub_command, expected_code",
    [
        ("add", 2),
        ("del", 2),
        ("disable", 2),
        ("enable", 2),
        ("get", 2),
        ("list", 0),
        ("user", 0),
        ("whoami", 2),
    ],
)
def test_unauthorized(sub_command, expected_code):
    out, err, code = call(["anchore-cli", "account", sub_command])
    assert code == ExitCode(expected_code)
    if expected_code == 2:
        assert err.startswith("Usage: anchore-cli account {}".format(sub_command))
    else:
        if sub_command == "list":
            assert out.startswith("Name")
        elif sub_command == "whoami":
            assert out.startswith("Unauthorized")
        else:
            assert out.startswith("Usage: anchore-cli account {}".format(sub_command))


class TesttList:
    def test_is_authorized(self, admin_call):
        out, err, code = admin_call(["account", "whoami"])
        assert code == ExitCode(0)
        assert "Username: admin" in out
        assert "AccountName: admin" in out
        assert "AccountEmail: admin@myanchore" in out
        assert "AccountType: admin" in out

    def test_is_authorized_json(self, admin_call):
        out, err, code = admin_call(["--json", "account", "whoami"])
        assert code == ExitCode(0)
        # only one account
        loaded = json.loads(out)
        account = loaded["account"]
        user = loaded["user"]
        assert account["email"] == "admin@myanchore"
        assert account["name"] == "admin"
        assert account["type"] == "admin"
        assert account["state"] == "enabled"
        assert user["source"] is None
        assert user["type"] == "native"
        assert user["username"] == "admin"


class TestWhoami:
    def test_is_authorized(self, admin_call):
        # get output in split lines, to avoid tabbing problems, real output is
        # not a list, just long lines
        out, err, code = admin_call(["account", "list"], split=True)
        assert code == 0
        assert out[0] == ["Name", "Email", "Type", "State", "Created"]
        # remove the TZ
        assert out[1][:-1] == ["admin", "admin@myanchore", "admin", "enabled"]

    def test_is_authorized_json(self, admin_call):
        out, err, code = admin_call(["--json", "account", "list"])
        assert code == ExitCode(0)
        # only one account
        loaded = json.loads(out)[0]
        assert loaded["email"] == "admin@myanchore"
        assert loaded["name"] == "admin"
        assert loaded["type"] == "admin"
        assert loaded["state"] == "enabled"
        assert "last_updated" in loaded


class TestDisable:
    def test_account_not_found(self, admin_call):
        out, err, code = admin_call(["account", "disable", "foo"])
        assert code == ExitCode(1)
        assert "Error: Account not found" in out
        assert "HTTP Code: 404" in out
        assert "Detail: {" in out
        assert "'error_codes': []" in out

    def test_disable_account(self, add_account, admin_call):
        account_name = add_account()
        out, err, code = admin_call(["account", "disable", account_name])
        assert code == ExitCode(0)
        assert out == "Success\n"

    def test_disable_account_fails_deleting(self, add_account, admin_call):
        account_name = add_account()
        admin_call(["account", "disable", account_name])
        admin_call(["account", "del", "--dontask", account_name])
        out, err, code = admin_call(["account", "disable", account_name])
        assert code == ExitCode(1)
        assert "Error: Invalid account state change requested." in out
        assert "Cannot go from state deleting to state disabled" in out

    def test_del_account_fails_deleting(self, add_account, admin_call):
        account_name = add_account()
        admin_call(["account", "disable", account_name])
        admin_call(["account", "del", "--dontask", account_name])
        out, err, code = admin_call(["account", "del", "--dontask", account_name])
        assert code == ExitCode(1)
        assert "Error: Invalid account state change requested." in out
        assert "Cannot go from state deleting to state deleting" in out
