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
