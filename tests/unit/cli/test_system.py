import pytest
from anchorecli.cli import system
from click.testing import CliRunner
import anchorecli.cli.utils
import anchorecli.clients.apiexternal


# feed response generator that can conditionally add group members in order to parameterize tests
@pytest.fixture
def make_feed_response():
    def _make_feed_response(additional_vuln_group_records=[]):
        groups = [
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

        groups += additional_vuln_group_records

        response = {
            "success": True,
            "httpcode": 200,
            "payload": [
                {
                    "name": "vulnerabilities",
                    "enabled": True,
                    "last_full_sync": "2020-12-23T19:34:29Z",
                    "updated_at": "2020-12-23T19:34:29Z",
                    "groups": groups,
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
def test_wait_for_feeds(monkeypatch, make_feed_response, test_context):
    monkeypatch.setattr(
        system, "config", {"url": "http://localhost:8228", "jsonmode": False}
    )
    monkeypatch.setattr(anchorecli.cli.utils, "check_access", lambda x: {})
    monkeypatch.setattr(
        anchorecli.clients.apiexternal,
        "system_status",
        lambda x: {"success": True, "httpcode": 200},
    )
    monkeypatch.setattr(
        anchorecli.clients.apiexternal,
        "system_feeds_list",
        lambda x: make_feed_response(test_context["additional_vuln_group_records"]),
    )

    runner = CliRunner()
    result = runner.invoke(system.wait, ["--servicesready", "", "--timeout", "5"])

    if test_context["expect_success"]:
        assert result.exit_code == 0
        assert "Feed sync: Success." in result.output
    else:
        assert result.exit_code == 2
        assert "Error: timed out" in result.output
