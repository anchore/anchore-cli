from conftest import call, ExitCode
import pytest
import json
import ipdb


input_image = "centos:latest"


@pytest.fixture
def image_command(admin_call):
    def apply(sub_command, flags):
        out, _, _ = admin_call(["--json", "image", sub_command] + flags)
        return json.loads(out)

    return apply


def test_image_add(image_command):
    result = image_command("add", [input_image])
    assert result[0]["image_status"] == "active"
    assert result[0]["image_detail"][0]["fulltag"] == "docker.io/centos:latest"


def test_image_list(image_command):
    result = image_command("list", [])
    assert result[0]["image_status"] == "active"
    assert result[0]["image_detail"][0]["fulltag"] == "docker.io/centos:latest"


def test_image_get(image_command):
    result = image_command("get", [input_image])
    assert result[0]["image_detail"][0]["fulltag"] == "docker.io/centos:latest"
