import pytest

from anchorecli.cli import event
from anchorecli.clients import apiexternal
from click.testing import CliRunner


@pytest.mark.parametrize(
    "input_level, expected_level, expected_code",
    [
        ("info", "info", None),
        ("INFO", "info", None),
        ("error", "error", None),
        ("ERROR", "error", None),
        ("other", None, 1)
    ],
)
def test_list_normalize_level(monkeypatch, input_level, expected_level, expected_code):
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
    if expected_code is not None:
        assert result.exit_code == expected_code
    else:
        assert normalized_level == [expected_level]
