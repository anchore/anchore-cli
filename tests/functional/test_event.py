import pytest
import json


input_image = "alpine:latest"


@pytest.fixture
def event_command(admin_call):
    def apply(sub_command, flags):
        output, _, _ = admin_call(["--json", "event", sub_command] + flags)
        return json.loads(output)

    return apply


class TestEvents:
    def test_event_list(self):
        pass

    def test_event_get(self):
        pass

    def test_event_delete(self):
        pass
