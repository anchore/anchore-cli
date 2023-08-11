import pytest
from anchorecli.cli import system
from click.testing import CliRunner
import anchorecli.cli.utils
import anchorecli.clients.apiexternal

# Patches all attributes needed for just testing the feeds wait
@pytest.fixture
def patch_for_feeds_wait(monkeypatch):
    monkeypatch.setattr(
        system, "config", {"url": "http://localhost:8228", "jsonmode": False}
    )
    monkeypatch.setattr(anchorecli.cli.utils, "check_access", lambda x: {})
    monkeypatch.setattr(
        anchorecli.clients.apiexternal,
        "system_status",
        lambda x: {"success": True, "httpcode": 200},
    )


# feed response generator that can conditionally add group members in order to parameterize tests
@pytest.fixture
def make_feed_response():
    def _make_feed_response(additional_vuln_group_records=[], vuln_enabled=True):
        vuln_groups = [
            {
                "created_at": "2020-03-27T22:48:57Z",
                "enabled": True,
                "last_sync": "2020-12-23T19:34:06Z",
                "name": "alpine:3.7",
                "record_count": 1412,
                "updated_at": "2020-12-23T19:34:07Z",
            },
            {
                "created_at": "2020-03-27T22:48:57Z",
                "enabled": True,
                "last_sync": "2020-12-23T19:33:29Z",
                "name": "centos:5",
                "record_count": 1347,
                "updated_at": "2020-12-23T19:34:06Z",
            },
        ]

        vuln_groups += additional_vuln_group_records

        response = {
            "success": True,
            "httpcode": 200,
            "payload": [
                {
                    "name": "vulnerabilities",
                    "enabled": vuln_enabled,
                    "last_full_sync": "2020-12-23T19:34:29Z",
                    "updated_at": "2020-12-23T19:34:29Z",
                    "groups": vuln_groups,
                }
            ],
        }

        return response

    return _make_feed_response


feed_wait_tests = [
    {"additional_vuln_group_records": [], "expect_success": True},
    {
        "additional_vuln_group_records": [
            {"name": "centos:7", "enabled": True, "last_sync": None, "record_count": 0}
        ],
        "expect_success": False,
    },
    {
        "additional_vuln_group_records": [
            {"name": "centos:7", "enabled": False, "last_sync": None, "record_count": 0}
        ],
        "expect_success": True,
    },
]


@pytest.mark.parametrize("test_context", feed_wait_tests)
def test_wait_for_group(
    monkeypatch, make_feed_response, test_context, patch_for_feeds_wait
):
    monkeypatch.setattr(
        anchorecli.clients.apiexternal,
        "system_feeds_list",
        lambda x: make_feed_response(
            additional_vuln_group_records=test_context["additional_vuln_group_records"]
        ),
    )

    runner = CliRunner()
    result = runner.invoke(system.wait, ["--servicesready", "", "--timeout", "5"])

    if test_context["expect_success"]:
        assert result.exit_code == 0
        assert "Feed sync: Success." in result.output
    else:
        assert result.exit_code == 2
        assert "Error: timed out" in result.output


def test_wait_for_disabled_feed(monkeypatch, make_feed_response, patch_for_feeds_wait):
    monkeypatch.setattr(
        anchorecli.clients.apiexternal,
        "system_feeds_list",
        lambda x: make_feed_response(vuln_enabled=False),
    )
    runner = CliRunner()
    result = runner.invoke(system.wait, ["--servicesready", "", "--timeout", "5"])
    assert result.exit_code == 2
    assert "Error: Requesting wait for disabled feed: vulnerabilities" in result.output


def test_wait_for_enabled_feed(monkeypatch, make_feed_response, patch_for_feeds_wait):
    monkeypatch.setattr(
        anchorecli.clients.apiexternal,
        "system_feeds_list",
        lambda x: make_feed_response(),
    )
    runner = CliRunner()
    result = runner.invoke(system.wait, ["--servicesready", "", "--timeout", "5"])
    assert result.exit_code == 0
    assert "Feed sync: Success" in result.output


class TestSystemSubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (system.status, "Usage: status"),
            (system.describe_errorcodes, "Usage: errorcodes"),
            (system.wait, "Usage: wait"),
            (system.delete, "Usage: del"),
            (system.feeds, "Usage: feeds"),
            (system.list, "Usage: list"),
            (system.feedsync, "Usage: sync"),
            (system.toggle_enabled, "Usage: config"),
            (system.delete_data, "Usage: delete"),
        ],
    )
    def test_event_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)
