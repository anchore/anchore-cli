import pytest
from anchorecli.cli import utils


class TestFormatErrorOutput:

    def setup(self):
        self.config = {'jsonmode': False}

    def test_fails_on_invalid_json(self):
        payload = Exception('could not access anchore service (user=None url=http://localhost:8228/v1)')
        result = utils.format_error_output(self.config, "policy", {}, payload)
        assert result == "Error: could not access anchore service (user=None url=http://localhost:8228/v1)\n"

    def test_empty_json_fallsback(self):
        result = utils.format_error_output(self.config, "policy", {}, "{}")
        assert result == '{}'

    def test_httpcode_is_included(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"httpcode": 200}')
        assert result == 'HTTP Code: 200\n'

    def test_message_is_included(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"message": "invalid input!"}')
        assert result == 'Error: invalid input!\n'

    def test_detail_is_included(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"detail": "\'id\' is missing"}')
        assert result == "Detail: 'id' is missing\n"


class TestFormatErrorOutputJSONMode:

    def setup(self):
        self.config = {'jsonmode': True}

    def test_loads_valid_json(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"message": "valid JSON"}')
        assert result == '{\n    "message": "valid JSON"\n}'

    def test_builds_valid_json_on_failure(self):
        result = utils.format_error_output(self.config, "policy", {}, 'invalid JSON!')
        assert result == '{\n    "message": "invalid JSON!"\n}'


class TestFormatErrorOutputAccountDelete:

    def setup(self):
        self.config = {'jsonmode': False}

    def test_invalid_account(self):
        result = utils.format_error_output(self.config, "account_delete", {}, '{"message": "Invalid account state change requested"}')
        assert 'Error: Invalid account state change requested' in result
        assert 'NOTE: accounts must be disabled (anchore-cli account disable <account>)' in result

    def test_state_change_is_valid(self):
        result = utils.format_error_output(self.config, "account_delete", {}, '{"message": "Unable to delete account"}')
        assert 'Error: Unable to delete account\n' == result


class TestCreateHint:

    def test_cannot_create_hint(self):
        result = utils.create_hint("should not create a hint here")
        assert result is None

    def test_creates_hint(self):
        result = utils.create_hint("'id' is a required property")
        assert 'Hint: The "id" key is not present in the JSON file' in result
        assert '"id": <value>' in result

    def test_cannot_create_hint_unquoted(self):
        result = utils.create_hint("unquoted_value is a required property")
        assert result is None

    @pytest.mark.parametrize('invalid_type', [None, [], {}, (), 1, True, False])
    def test_handles_non_strings(self, invalid_type):
        result = utils.create_hint(invalid_type)
        assert result is None


class TestFormatVulnerabilities:

    def test_no_query_type(self):
        payload = ['os', 'non-os', 'all']
        result = utils.format_vulnerabilities(payload, {})
        lines = result.split('\n')
        assert lines[0] == 'os: available'
        assert lines[1] == 'non-os: available'
        assert lines[2] == 'all: available'

    def test_os_nonos_all_header(self, payload):
        result = utils.format_vulnerabilities(payload, {'query_type': 'all'})
        header = result.split('\n')[0].split()
        assert header == [
            'Vulnerability', 'ID', 'Package', 'Severity', 'Fix', 'CVE',  'Refs',
            'Vulnerability',  'URL', 'Type', 'Feed', 'Group', 'Package', 'Path'
        ]

    def test_all(self, payload):
        result = utils.format_vulnerabilities(payload, {'query_type': 'all'})
        line = result.split('\n')[1].split()
        assert line == [
            'RHSA-2019:4190',
            'nss-3.44.0-4.el7',
            'High',
            '0:3.44.0-7.el7_7',
            'CVE-2019-11729,CVE-2019-11745',
            'https://access.redhat.com/errata/RHSA-2019:4190',
            'rpm',
            'centos:7',
            'None',
        ]

    def test_vulnerability_id_missing(self, payload):
        result = utils.format_vulnerabilities(payload, {'query_type': 'all'})
        line = result.split('\n')[-1].split()
        assert line == [
            'RHSA-2019:4190',
            'nss-util-3.44.0-3.el7',
            'High',
            '0:3.44.0-4.el7_7',
            'CVE-2019-11745',
            'https://access.redhat.com/errata/RHSA-2019:4190',
            'rpm',
            'centos:7',
            'None',
        ]
