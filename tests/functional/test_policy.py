import pytest
import json

input_policy = "foo"

@pytest.fixture
def policy_command(admin_call):
    def apply(sub_command, flags):
        out, _, _ = admin_call(["--json", "policy", sub_command] + flags)
        return json.loads(out)
    return apply


class TestPolicyCMD:

    def test_policy_add(self, policy_command):
        result = policy_command("add", input_policy)
        print(result)

    def test_policy_get(self, policy_command):
        result = policy_command("get", input_policy_id)
