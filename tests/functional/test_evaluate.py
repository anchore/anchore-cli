# evaluation datastructure [ {digest: { input_image: [ { detail: {}, last_eval: "", policyid: "", status: "" } ] } ]
import pytest
import json
from conftest import ExitCode

input_image = "centos:latest"


@pytest.fixture
def eval_command(admin_call):
    def apply(sub_command, flags):
        out, err, code = admin_call(["--json", "evaluate", sub_command] + flags)
        return out, err, code

    return apply


def test_check(eval_command):
    res, err, code = eval_command("check", [input_image])
    result = json.loads(res)
    print(result)
