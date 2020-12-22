import pytest

from anchorecli.cli import event
from anchorecli.clients import apiexternal
from click.testing import CliRunner


@pytest.mark.parametrize(
    "input_level, expected_level",
    [
        ("info", "info"),
        ("INFO", "info"),
        ("error", "error"),
        ("ERROR", "error"),
    ],
)
def test_list_normalize_level(monkeypatch, input_level, expected_level):
    normalized_level = []

    def mock_method(
        config,
        since=None,
        before=None,
        level=None,
        service=None,
        host=None,
        resource=None,
        resource_type=None,
        event_type=None,
        all=False,
    ):
        normalized_level.append(level)

    monkeypatch.setattr(
        apiexternal,
        "list_events",
        mock_method,
    )
    runner = CliRunner()
    result = runner.invoke(event.list, ["--level", input_level])
    assert normalized_level == [expected_level]
