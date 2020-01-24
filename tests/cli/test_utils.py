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
