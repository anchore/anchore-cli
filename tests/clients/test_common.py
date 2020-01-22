import pytest
from anchorecli.clients.common import make_client_result


class TestMakeClientResult:

    def test_result_is_success(self, stub_response):
        response = stub_response()
        result = make_client_result(response)
        assert result['httpcode'] == 200
        assert result['success'] is True

    @pytest.mark.parametrize("code", [i for i in range(200, 299)])
    def test_success_in_200_range(self, stub_response, code):
        response = stub_response(status_code=code)
        result = make_client_result(response)
        assert result['success'] is True

    def test_raw_payload(self, stub_response):
        response = stub_response(text="raw json")
        result = make_client_result(response, raw=True)
        assert result['payload'] == "raw json"

    def test_payload_loads(self, stub_response):
        response = stub_response(json_text={})
        result = make_client_result(response)
        assert result['payload'] == {}

    def test_payload_loads_fallsback_on_invalid(self, stub_response):
        response = stub_response(text="invalid json")
        result = make_client_result(response)
        assert result['payload'] == "invalid json"

    def test_result_fails(self, stub_response):
        response = stub_response(status_code=500)
        result = make_client_result(response)
        assert result['success'] is False

    def test_raw_payload_fails(self, stub_response):
        response = stub_response(status_code=500, text="raw json")
        result = make_client_result(response, raw=True)
        assert result['error'] == "raw json"

    def test_payload_loads_fails(self, stub_response):
        response = stub_response(status_code=500, json_text={})
        result = make_client_result(response)
        assert result['error'] == {}

    def test_payload_loads_fallsback_on_invalid_fails(self, stub_response):
        response = stub_response(status_code=500, text="invalid json")
        result = make_client_result(response)
        assert result['error'] == "invalid json"

    def test_401_failure_message(self, stub_response):
        response = stub_response(status_code=401, text=None)
        result = make_client_result(response)
        assert result['error'] == "Unauthorized - please check your username/password"

    def test_exception_breaks_everything(self):
        with pytest.raises(AttributeError):
            make_client_result(None)
