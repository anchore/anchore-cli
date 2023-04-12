import pytest
import json


@pytest.fixture
def query_command(admin_call):
    def apply(sub_command, flags):
        out, _, _ = admin_call(["--json", "query", sub_command] + flags)
        return json.loads(out)

    return apply


def test_image_by_vulnerability(query_command):
    pass
