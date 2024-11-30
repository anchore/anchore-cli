import pytest
import json


@pytest.fixture
def system_command(admin_call):
    def apply(sub_command, flags):
        out, _, _ = admin_call(["--json", "system", sub_command] + flags)
        return json.loads(out)

    return apply


class TestSystemStatus:
    @staticmethod
    def _search_dict(name, col):
        for entry in col:
            if entry["servicename"] == name:
                return entry

    def test_system_status(self, system_command):
        services = ["apiext", "catalog", "analyzer", "policy_engine", "simplequeue"]
        result = system_command("status", [])
        for srv_name in services:
            asset = self._search_dict(srv_name, result["service_states"])
            assert asset["servicename"] == srv_name
            assert asset["service_detail"]["message"] == "all good"
            assert asset["service_detail"]["available"]
            assert asset["status_message"] == "available"
            assert asset["service_detail"]["up"]
