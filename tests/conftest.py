import json
import pytest


class Factory(object):

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


@pytest.fixture
def stub_response():
    def apply(status_code=200, text="", json_text=None):
        if json_text is not None:
            text = json.dumps(json_text)
        response = Factory(status_code=status_code, text=text)
        return response
    return apply


@pytest.fixture(autouse=True)
def no_fds_closing(monkeypatch):
    """
    The ClickRunner test helper breaks when stdout and stderr is closed as it is trying to capture
    whatever the tool was sending as output. This env is prevents anchore-cli from closing them
    allowing the ClickRunner to work.

    Related issues:

    * https://github.com/pallets/click/issues/824
    * https://github.com/pytest-dev/pytest/issues/3344
    """
    monkeypatch.setenv('ANCHORE_CLI_NO_FDS_CLEANUP', '1')
